package endless

import (
	"net"
	"os"
	"syscall"
	"time"
)

type endlessListener struct {
	net.Listener
	stopped bool
	server  *endlessServer
}

func newEndlessListener(listener net.Listener, server *endlessServer) (el *endlessListener) {
	el = &endlessListener{
		Listener: listener,
		server:   server,
	}

	return
}

func (listener *endlessListener) Accept() (net.Conn, error) {
	tcpConn, err := listener.Listener.(*net.TCPListener).AcceptTCP()
	if err != nil {
		return nil, err
	}

	_ = tcpConn.SetKeepAlive(true)                  // see http.tcpKeepAliveListener
	_ = tcpConn.SetKeepAlivePeriod(3 * time.Minute) // see http.tcpKeepAliveListener

	conn := endlessConn{
		Conn:   tcpConn,
		server: listener.server,
	}

	listener.server.waitGroup.Add(1)

	return conn, nil
}

func (listener *endlessListener) Close() error {
	if listener.stopped {
		return syscall.EINVAL
	}

	listener.stopped = true
	return listener.Listener.Close()
}

func (listener *endlessListener) File() *os.File {
	// returns a dup(2) - FD_CLOEXEC flag *not* set
	tl := listener.Listener.(*net.TCPListener)
	fl, _ := tl.File()
	return fl
}
