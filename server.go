package endless

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	PRE_SIGNAL = iota
	POST_SIGNAL

	STATE_INIT
	STATE_RUNNING
	STATE_SHUTTING_DOWN
	STATE_TERMINATE
)

const empty_string = ""

var (
	runningServerReg     sync.RWMutex
	runningServers       map[string]*endlessServer // addr-> server
	runningServersOrder  []string                  // addr数组
	socketPtrOffsetMap   map[string]uint           // addr -> offset
	runningServersForked bool

	DefaultReadTimeOut    time.Duration
	DefaultWriteTimeOut   time.Duration
	DefaultMaxHeaderBytes int
	DefaultHammerTime     time.Duration

	socketOrder string

	hookableSignals []os.Signal
)

func init() {
	runningServerReg = sync.RWMutex{}
	runningServers = make(map[string]*endlessServer)
	runningServersOrder = []string{}
	socketPtrOffsetMap = make(map[string]uint)

	DefaultMaxHeaderBytes = 0 // use http.DefaultMaxHeaderBytes - which currently is 1 << 20 (1MB)

	// after a restart the parent will finish ongoing requests before shutting down. set to a negative value to disable
	DefaultHammerTime = 60 * time.Second

	hookableSignals = []os.Signal{
		syscall.SIGHUP,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGTSTP,
	}
}

type endlessServer struct {
	http.Server
	listener net.Listener
	// int(当前是在什么时候)->signal->[]func()
	SignalHooks      map[int]map[os.Signal][]func()
	tlsInnerListener *endlessListener
	waitGroup        sync.WaitGroup
	signalChan       chan os.Signal
	isChild          bool
	state            uint8
	lock             *sync.RWMutex
}

func NewServer(addr string, handler http.Handler) (server *endlessServer) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	socketOrder = os.Getenv("ENDLESS_SOCKET_ORDER")

	if len(socketOrder) > 0 {
		socketPtrOffsetMap[addr] = uint(len(strings.Split(socketOrder, ",")) - 1)
	} else {
		socketPtrOffsetMap[addr] = uint(len(runningServersOrder))
	}

	server = &endlessServer{
		waitGroup:  sync.WaitGroup{},
		signalChan: make(chan os.Signal),
		isChild:    os.Getenv("ENDLESS_CONTINUE") != "",
		SignalHooks: map[int]map[os.Signal][]func(){
			PRE_SIGNAL: {
				syscall.SIGHUP:  {},
				syscall.SIGUSR1: {},
				syscall.SIGUSR2: {},
				syscall.SIGINT:  {},
				syscall.SIGTERM: {},
				syscall.SIGTSTP: {},
			},
			POST_SIGNAL: {
				syscall.SIGHUP:  {},
				syscall.SIGUSR1: {},
				syscall.SIGUSR2: {},
				syscall.SIGINT:  {},
				syscall.SIGTERM: {},
				syscall.SIGTSTP: {},
			},
		},
		state: STATE_INIT,
		lock:  &sync.RWMutex{},
	}

	server.Server.Addr = addr
	server.Server.ReadTimeout = DefaultReadTimeOut
	server.Server.WriteTimeout = DefaultWriteTimeOut
	server.Server.MaxHeaderBytes = DefaultMaxHeaderBytes
	server.Server.Handler = handler

	runningServersOrder = append(runningServersOrder, addr)
	runningServers[addr] = server

	return
}

func ListenAndServe(addr string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServe()
}

/*
	act identically to ListenAndServe, except that it expects

HTTPS connections. Additionally, files containing a certificate and matching
private key for the server must be provided. If the certificate is signed by a
certificate authority, the certFile should be the concatenation of the server's
certificate followed by the CA's certificate.
*/
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler http.Handler) error {
	server := NewServer(addr, handler)
	return server.ListenAndServeTLS(certFile, keyFile)
}

func (server *endlessServer) getState() uint8 {
	server.lock.RLock()
	defer server.lock.RUnlock()

	return server.state
}

func (server *endlessServer) setState(st uint8) {
	server.lock.Lock()
	defer server.lock.Unlock()

	server.state = st
}

func (server *endlessServer) Serve() (err error) {
	defer log.Println(syscall.Getpid(), "Serve() returning...")

	server.setState(STATE_RUNNING)
	err = server.Server.Serve(server.listener)
	log.Println(syscall.Getpid(), "Waiting for connections to finish...")
	server.waitGroup.Wait()
	server.setState(STATE_TERMINATE)
	return
}

func (server *endlessServer) ListenAndServe() (err error) {
	addr := server.Addr
	if addr == "" {
		addr = ":http"
	}

	go server.handleSignals()

	listener, err := server.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	server.listener = newEndlessListener(listener, server)

	if server.isChild {
		_ = syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	return server.Serve()
}

func (server *endlessServer) ListenAndServeTLS(certFile, keyFile string) (err error) {
	addr := server.Addr
	if addr == "" {
		addr = ":https"
	}

	config := &tls.Config{}
	if server.TLSConfig != nil {
		*config = *server.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	go server.handleSignals()

	l, err := server.getListener(addr)
	if err != nil {
		log.Println(err)
		return
	}

	server.tlsInnerListener = newEndlessListener(l, server)
	server.listener = tls.NewListener(server.tlsInnerListener, config)

	if server.isChild {
		syscall.Kill(syscall.Getppid(), syscall.SIGTERM)
	}

	log.Println(syscall.Getpid(), server.Addr)
	return server.Serve()
}

// either opens a new socket to listen on, or takes the acceptor socket it got passed when restarted.
func (server *endlessServer) getListener(addr string) (net.Listener, error) {
	var listener net.Listener

	if server.isChild {
		var ptrOffset uint = 0

		runningServerReg.RLock()
		defer runningServerReg.RUnlock()

		if len(socketPtrOffsetMap) > 0 {
			ptrOffset = socketPtrOffsetMap[addr]
			// log.Println("laddr", laddr, "ptr offset", socketPtrOffsetMap[laddr])
		}

		listener2, err := net.FileListener(os.NewFile(uintptr(3+ptrOffset), empty_string))
		if err != nil {
			err = fmt.Errorf("net.FileListener error: %v", err)
			return nil, err
		}

		listener = listener2
	} else { // 标准的套路
		listener0, err := net.Listen("tcp", addr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return nil, err
		}

		listener = listener0
	}

	return listener, nil
}

// listen for os Signals and calls any hooked in function that the user had registered with the signal.
func (server *endlessServer) handleSignals() {
	signal.Notify(server.signalChan, hookableSignals...)

	pid := syscall.Getpid()

	for {
		sig := <-server.signalChan

		server.signalHooks(PRE_SIGNAL, sig)

		switch sig {
		case syscall.SIGHUP:
			log.Println(pid, "Received SIGHUP. forking.")

			err := server.fork()
			if err != nil {
				log.Println("Fork err:", err)
			}
		case syscall.SIGUSR1:
			log.Println(pid, "Received SIGUSR1.")
		case syscall.SIGUSR2:
			log.Println(pid, "Received SIGUSR2.")
			server.hammerTime(0 * time.Second)
		case syscall.SIGINT:
			log.Println(pid, "Received SIGINT.")
			server.shutdown()
		case syscall.SIGTERM:
			log.Println(pid, "Received SIGTERM.")
			server.shutdown()
		case syscall.SIGTSTP:
			log.Println(pid, "Received SIGTSTP.")
		default:
			log.Printf("Received %v: nothing i care about...\n", sig)
		}

		server.signalHooks(POST_SIGNAL, sig)
	}
}

func (server *endlessServer) signalHooks(stage int, sig os.Signal) {
	if _, notSet := server.SignalHooks[stage][sig]; !notSet {
		return
	}

	for _, function := range server.SignalHooks[stage][sig] {
		function()
	}

	return
}

/*
shutdown closes the listener so that no new connections are accepted. it also
starts a goroutine that will hammer (stop all running requests) the server
after DefaultHammerTime.
*/
func (server *endlessServer) shutdown() {
	if server.getState() != STATE_RUNNING {
		return
	}

	server.setState(STATE_SHUTTING_DOWN)

	if DefaultHammerTime >= 0 {
		go server.hammerTime(DefaultHammerTime)
	}

	// disable keep-alives on existing connections
	server.SetKeepAlivesEnabled(false)

	err := server.listener.Close()
	if err != nil {
		log.Println(syscall.Getpid(), "listener.Close() error:", err)
	} else {
		log.Println(syscall.Getpid(), server.listener.Addr(), "listener closed.")
	}
}

/*
hammerTime forces the server to shutdown in a given timeout - whether it
finished outstanding requests or not. if Read/WriteTimeout are not set or the
max header size is very big a connection could hang...

srv.Serve() will not return until all connections are served. this will
unblock the srv.waitGroup.Wait() in Serve() thus causing ListenAndServe(TLS) to
return.
*/
func (server *endlessServer) hammerTime(d time.Duration) {
	defer func() {
		// we are calling server.waitGroup.Done() until it panics which means we called
		// Done() when the counter was already at 0 and we're done.
		// (and thus Serve() will return and the parent will exit)
		if r := recover(); r != nil {
			log.Println("WaitGroup at 0", r)
		}
	}()

	if server.getState() != STATE_SHUTTING_DOWN {
		return
	}

	time.Sleep(d)

	log.Println("[STOP - Hammer Time] Forcefully shutting down parent")

	for {
		if server.getState() == STATE_TERMINATE {
			break
		}
		server.waitGroup.Done()
		runtime.Gosched()
	}
}

func (server *endlessServer) fork() (err error) {
	runningServerReg.Lock()
	defer runningServerReg.Unlock()

	// only one server instance should fork!
	if runningServersForked {
		return errors.New("Another process already forked. Ignoring this one.")
	}
	runningServersForked = true

	var files = make([]*os.File, len(runningServers))
	var orderArgs = make([]string, len(runningServers))

	// get the accessor socket fds for _all_ server instances
	for _, server_ := range runningServers {
		// introspect.PrintTypeDump(server_.listener)
		switch server_.listener.(type) {
		case *endlessListener:
			// normal listener
			files[socketPtrOffsetMap[server_.Server.Addr]] = server_.listener.(*endlessListener).File()
		default:
			// tls listener
			files[socketPtrOffsetMap[server_.Server.Addr]] = server_.tlsInnerListener.File()
		}

		orderArgs[socketPtrOffsetMap[server_.Server.Addr]] = server_.Server.Addr
	}

	env := append(
		os.Environ(), "ENDLESS_CONTINUE=1",
	)

	if len(runningServers) > 1 {
		env = append(env, fmt.Sprintf(`ENDLESS_SOCKET_ORDER=%s`, strings.Join(orderArgs, ",")))
	}

	// log.Println(files)
	path := os.Args[0]
	var args []string
	if len(os.Args) > 1 {
		args = os.Args[1:]
	}

	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files
	cmd.Env = env

	// cmd.SysProcAttr = &syscall.SysProcAttr{
	// 	Setsid:  true,
	// 	Setctty: true,
	// 	Ctty:    ,
	// }

	err = cmd.Start()
	if err != nil {
		log.Fatalf("Restart: Failed to launch, error: %v", err)
	}

	return
}

type endlessConn struct {
	net.Conn
	server *endlessServer
}

func (conn endlessConn) Close() error {
	err := conn.Conn.Close()
	if err == nil {
		conn.server.waitGroup.Done()
	}
	return err
}

func (server *endlessServer) RegisterSignalHook(stage int, sig os.Signal, f func()) (err error) {
	if stage != PRE_SIGNAL && stage != POST_SIGNAL {
		err = fmt.Errorf("Cannot use %v for stage arg. Must be endless.PRE_SIGNAL or endless.POST_SIGNAL.", sig)
		return
	}
	for _, s := range hookableSignals {
		if s == sig {
			server.SignalHooks[stage][sig] = append(server.SignalHooks[stage][sig], f)
			return
		}
	}
	err = fmt.Errorf("Signal %v is not supported.", sig)
	return
}
