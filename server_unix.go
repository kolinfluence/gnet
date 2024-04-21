// Copyright 2019 Andy Pan. All rights reserved.
// Copyright 2018 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly
// +build linux darwin netbsd freebsd openbsd dragonfly

package gnet

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/kolinfluence/gnet/pkg/errors"

	"github.com/kolinfluence/gnet/internal/netpoll"
	"github.com/luyu6056/tls"
	"golang.org/x/sys/unix"
)

type server struct {
	ln               *listener          // all the listeners
	wg               sync.WaitGroup     // loop close WaitGroup
	opts             *Options           // options with server
	once             sync.Once          // make sure only signalShutdown once
	cond             *sync.Cond         // shutdown signaler
	codec            ICodec             // codec for TCP stream
	ticktock         chan time.Duration // ticker channel
	mainLoop         *eventloop         // main loop for accepting connections
	eventHandler     EventHandler       // user eventHandler
	subLoopGroup     IEventLoopGroup    // loops for handling events
	subLoopGroupSize int                // number of loops
	Isblock          bool               //允许阻塞
	tlsconfig        *tls.Config
	close            chan bool
	connections      sync.Map // loop connections fd -> conn
	connWg           *sync.WaitGroup
}

// waitForShutdown waits for a signal to shutdown
func (srv *server) waitForShutdown() {
	srv.cond.L.Lock()
	srv.cond.Wait()
	srv.cond.L.Unlock()
	srv.stop()
}

// signalShutdown signals a shutdown an begins server closing
func (srv *server) signalShutdown() {
	srv.once.Do(func() {
		srv.cond.L.Lock()
		srv.cond.Signal()
		srv.cond.L.Unlock()
	})
}

func (srv *server) startLoops() {
	srv.subLoopGroup.iterate(func(i int, lp *eventloop) bool {
		srv.wg.Add(1)
		go func() {
			lp.loopOut()
			lp.loopRun()
			srv.wg.Done()
		}()
		return true
	})
}
func (srv *server) closeConns() {
	srv.connections.Range(func(key, value interface{}) bool {
		c := value.(*conn)
		c.loopCloseConn(errors.ErrEngineShutdown)
		return true
	})
	srv.connWg.Wait()

}
func (srv *server) closeLoops() {
	select {
	case srv.close <- true:
	default:

	}

	srv.closeConns()
	var wg sync.WaitGroup
	srv.subLoopGroup.iterate(func(i int, lp *eventloop) bool {
		wg.Add(1)
		sniffError(lp.poller.Trigger(func(_ interface{}) error {

			return errors.ErrEngineShutdown
		}, nil))
		lp.outclose <- true
		go func() {
			<-lp.outclose
			wg.Done()
		}()

		return true
	})
	wg.Wait()
}

func (srv *server) startReactors() {
	srv.subLoopGroup.iterate(func(i int, el *eventloop) bool {
		srv.wg.Add(1)
		go func() {
			el.loopOut()
			srv.activateSubReactor(el)
			srv.wg.Done()
		}()
		return true
	})
}

func (srv *server) activateLoops(numLoops int) error {
	// Create loops locally and bind the listeners.

	for i := 0; i < numLoops; i++ {
		if p, err := netpoll.OpenPoller(); err == nil {
			el := &eventloop{
				idx:          i,
				srv:          srv,
				codec:        srv.codec,
				poller:       p,
				packet:       make([]byte, 0xFFFF),
				eventHandler: srv.eventHandler,
			}

			el.pollAttachment = netpoll.GetPollAttachment()
			el.pollAttachment.FD = srv.ln.fd
			el.pollAttachment.Callback = el.handleEvent
			_ = el.poller.AddRead(el.pollAttachment)
			srv.subLoopGroup.register(el)
		} else {
			return err
		}
	}

	srv.subLoopGroupSize = srv.subLoopGroup.len()
	// Start loops in background
	srv.startLoops()
	return nil
}

func (srv *server) activateReactors(numLoops int) error {
	if p, err := netpoll.OpenPoller(); err == nil {
		el := &eventloop{
			idx:      -1,
			poller:   p,
			srv:      srv,
			outclose: make(chan bool, 1),
		}
		el.pollAttachment = netpoll.GetPollAttachment()
		el.pollAttachment.FD = srv.ln.fd
		el.pollAttachment.Callback = srv.activateMainReactorCallback
		_ = el.poller.AddRead(el.pollAttachment)
		srv.mainLoop = el
		// Start main reactor.
		srv.wg.Add(1)
		go func() {

			srv.activateMainReactor()
			srv.wg.Done()
		}()
	} else {
		return err
	}
	for i := 0; i < numLoops; i++ {
		if p, err := netpoll.OpenPoller(); err == nil {
			el := &eventloop{
				idx:          i,
				srv:          srv,
				codec:        srv.codec,
				poller:       p,
				packet:       make([]byte, 0xFFFF),
				eventHandler: srv.eventHandler,
			}

			srv.subLoopGroup.register(el)
		} else {
			return err
		}
	}
	srv.subLoopGroupSize = srv.subLoopGroup.len()
	// Start sub reactors.
	srv.startReactors()

	return nil
}

func (srv *server) activateMainReactorCallback(fd int) error {
	return srv.acceptNewConnection(fd)
}

func (srv *server) start(numCPU int) error {
	if srv.opts.ReusePort || srv.ln.pconn != nil {
		return srv.activateLoops(numCPU)
	}
	return srv.activateReactors(numCPU)
}

func (srv *server) stop() {
	srv.waitClose()
	// Close loops and all outstanding connections
	srv.closeLoops()

	// Wait on all loops to complete reading events

	// Notify all loops to close by closing all listeners

	if srv.mainLoop != nil {
		sniffError(srv.mainLoop.poller.Trigger(func(_ interface{}) error {

			return errors.ErrEngineShutdown
		}, nil))
	}
	srv.wg.Wait()

	if srv.mainLoop != nil {
		sniffError(srv.mainLoop.poller.Close())
		srv.mainLoop.outclose <- true

	}
}

// tcp平滑重启，开启ReusePort有效，关闭ReusePort则会造成短暂的错误

func serve(eventHandler EventHandler, addr string, options *Options) error {
	// Create new server instance
	srv := new(server)
	srv.connWg = new(sync.WaitGroup)

	// Parse network and address
	ln := listener{
		network: parseNetwork(addr),
		addr:    parseAddress(addr),
	}

	// Configure listener with socket options
	listenCfg := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	// Create the listener using ListenConfig
	listener, err := listenCfg.Listen(context.Background(), ln.network, ln.addr)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", ln.addr, err)
		return err
	}
	defer listener.Close()
	log.Printf("Listening on %s", listener.Addr().String())
	srv.ln = &ln
	srv.ln.ln = listener

	// Handle flags for graceful reload or stop
	flag.Parse()
	if flag.Lookup("stop") != nil && flag.Lookup("stop").Value.(flag.Getter).Get().(bool) {
		return handleStop(options)
	}
	if flag.Lookup("reload") != nil && flag.Lookup("reload").Value.(flag.Getter).Get().(bool) {
		return handleReload(options)
	}

	// Continue setup for your server
	srv.opts = options
	srv.tlsconfig = options.Tlsconfig
	srv.eventHandler = eventHandler
	srv.subLoopGroup = new(eventLoopGroup)
	srv.cond = sync.NewCond(&sync.Mutex{})
	srv.ticktock = make(chan time.Duration, 1)
	srv.Isblock = options.Isblock
	srv.codec = getDefaultCodec(options)

	// Determine the number of loops or goroutines
	numCPU := determineCPU(options)

	server := Server{
		Multicore:    numCPU > 1,
		Addr:         listener.Addr().String(),
		NumEventLoop: numCPU,
		TCPKeepAlive: options.TCPKeepAlive,
		Close:        func() { srv.close <- true },
	}

	if srv.eventHandler.OnInitComplete(server) == Shutdown {
		return nil
	}

	if err := srv.start(numCPU); err != nil {
		srv.closeLoops()
		log.Printf("Server is stopping with error: %v", err)
		return err
	}

	srv.waitForShutdown()
	return nil
}

func (srv *server) signalHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1)
	select {
	case sig := <-ch:
		signal.Stop(ch)
		var wg, wg1 sync.WaitGroup
		wg.Add(srv.subLoopGroup.len())
		wg1.Add(1)
		srv.subLoopGroup.iterate(func(i int, lp *eventloop) bool {
			sniffError(lp.poller.Trigger(func(_ interface{}) error {
				wg.Done()
				wg1.Wait()
				return nil
			}, nil))
			return true
		})
		wg.Wait()
		srv.ln.fd = 0 // 修改监听fd让accept失效
		wg1.Done()
		// timeout context for shutdown
		switch sig {
		case syscall.SIGINT, syscall.SIGTERM:
			// stop
			log.Println("signal: stop")
			srv.signalShutdown()
			return
		case syscall.SIGUSR1:
			if srv.ln != nil {
				// reload
				f, err := srv.ln.ln.(*net.TCPListener).File()
				var args []string
				if err == nil {
					args = []string{"-graceful"}
				}
				cmd := exec.Command(os.Args[0], args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				// put socket FD at the first entry
				cmd.ExtraFiles = []*os.File{f}
				cmd.Start()
				srv.signalShutdown()
			}

			return
		}
	case <-srv.close:
		log.Println("close gnet")
		srv.signalShutdown()
		return
	}

}

func (srv *server) waitClose() {

	var wg sync.WaitGroup
	srv.connections.Range(func(key, value interface{}) bool {
		c := value.(*conn)
		wg.Add(1)
		_ = c.loop.poller.Trigger(func(i interface{}) error {
			if c != nil {
				if c.state == connStateOk {
					srv.eventHandler.SignalClose(c)
				}
			}

			wg.Done()
			return nil
		}, nil)
		return true
	})
	wg.Wait()

}
