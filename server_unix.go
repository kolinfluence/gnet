// Copyright 2019 Andy Pan. All rights reserved.
// Copyright 2018 Joshua J Baker. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

//go:build linux || darwin || netbsd || freebsd || openbsd || dragonfly
// +build linux darwin netbsd freebsd openbsd dragonfly

package gnet

import (
	"context"  // Make sure context is imported
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
    	"errors"  // Import the built-in errors package
	
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
    // Check if necessary components are initialized
    if srv.ln == nil || srv.ln.fd == 0 {
        return errors.New("listener or listener fd is nil")
    }
    if srv.opts.ReusePort || srv.ln.pconn != nil {
        return srv.activateLoops(numCPU)
    }
    return srv.activateReactors(numCPU)
}

func (srv *server) activateLoops(numLoops int) error {
    if srv.subLoopGroup == nil {
        srv.subLoopGroup = newEventLoopGroup() // Ensure subLoopGroup is initialized
    }
    
    for i := 0; i < numLoops; i++ {
        p, err := netpoll.OpenPoller()
        if err != nil {
            return err
        }
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
        if err := el.poller.AddRead(el.pollAttachment); err != nil {
            return err
        }
        srv.subLoopGroup.register(el)
    }

    srv.subLoopGroupSize = srv.subLoopGroup.len()
    srv.startLoops()
    return nil
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

func serve(eventHandler EventHandler, addr string, options *Options) error {
    srv := new(server)
    srv.connWg = new(sync.WaitGroup)
    var ln listener
    ln.network, ln.addr = parseAddr(addr)

    listenCfg := net.ListenConfig{
        Control: func(network, address string, c syscall.RawConn) error {
            return c.Control(func(fd uintptr) {
                if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
                    log.Printf("Failed to set SO_REUSEADDR: %v", err)
                }
                if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
                    log.Printf("Failed to set SO_REUSEPORT: %v", err)
                }
            })
        },
    }

    listener, err := listenCfg.Listen(context.Background(), "tcp", ln.addr)
    if err != nil {
        log.Printf("Failed to listen on %s: %v", ln.addr, err)
        return err
    }
    defer listener.Close()
    log.Printf("Listening on %s", listener.Addr().String())

    srv.ln = &ln
    srv.ln.ln = listener

    var reload, graceful, stop bool
    if options.Graceful {
        flag.BoolVar(&reload, "reload", false, "listen on fd open 3 (internal use only)")
        flag.BoolVar(&graceful, "graceful", false, "listen on fd open 3 (internal use only)")
        flag.BoolVar(&stop, "stop", false, "stop the server from pid")
        flag.Parse()
    }

    if stop {
        handleStop(options.PidName)
        return nil  // Adjust to not return error here
    }
    if reload {
        handleReload(options.PidName)
        return nil  // Adjust to not return error here
    }

    // Correcting the srv.start call to pass a proper integer (Number of CPUs)
    numCPU := runtime.NumCPU()  // reintroduce runtime appropriately if needed elsewhere
    if err := srv.start(numCPU); err != nil {
        log.Printf("Server start failed: %v", err)
        return err
    }

    srv.waitForShutdown()
    return nil
}

func handleStop(pidName string) {
    b, err := ioutil.ReadFile("./" + pidName)
    if err != nil {
        log.Println("Failed to read PID file:", err)
        return
    }
    pid, err := strconv.Atoi(string(b))
    if err != nil {
        log.Println("Invalid PID:", err)
        return
    }
    if err = syscall.Kill(pid, syscall.SIGTERM); err != nil {
        log.Println("Failed to stop server:", err)
    } else {
        log.Println("Server stopped successfully")
    }
}

func handleReload(pidName string) {
    b, err := ioutil.ReadFile("./" + pidName)
    if err != nil {
        log.Println("Failed to read PID file for reload:", err)
        return
    }
    pid, err := strconv.Atoi(string(b))
    if err != nil {
        log.Println("Invalid PID for reload:", err)
        return
    }
    if err = syscall.Kill(pid, syscall.SIGUSR1); err != nil {
        log.Println("Failed to reload server:", err)
    } else {
        log.Println("Server reloaded successfully")
    }
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
