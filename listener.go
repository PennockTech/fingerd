// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// TCPFingerListener wraps up everything around listening for connections on a
// per-protocol basis.  We do not assume sockets accept both IPv4 and IPv6, so
// instead individually explicitly bind each.  (That's a portability issue, the
// BSDs switched to blocking both by default on a v6 socket, Linux still does
// both by default, and both allow this default to by changed via sysctl/proc,
// or on a per-socket basis.)
type TCPFingerListener struct {
	// The logger is only used once in spawned go-routines; within the main control, errors are returned
	// to the caller to log as appropriate
	*logrus.Entry

	networkFamily string
	active        *sync.WaitGroup
	shuttingDown  <-chan struct{}
	tcpListener   *net.TCPListener
}

// TCPFingerConnection is the state for one connection.  It has fields which
// mutate on a per-user basis when handling multiple user-names on one
// connection.
type TCPFingerConnection struct {
	*logrus.Entry
	conn *net.TCPConn
	l    *TCPFingerListener

	// Did the request use CRLF?  It should have, but if not then adapt and don't send back CRLF lines.
	crlf bool
	// Has long-mode output been requested?
	long bool

	// Changes during the lifetime of the connection as we process each user in turn
	username string
	homeDir  string
	// Set if we expect the uid to be a certain value, as a security test
	uid uint32 // fgrep Uid syscall/ztypes_*
	// writeError says "we've seen an error writing, abort abort
	writeError bool
}

// NewTCPFingerListener wraps up the normal path for creating a finger listener.
// Note that we can also manually construct the type via inheritedListeners() for
// when we've re-exec'd ourselves.
func NewTCPFingerListener(
	networkFamily string,
	wg *sync.WaitGroup,
	shuttingDown <-chan struct{},
	logger *logrus.Logger,
) (*TCPFingerListener, error) {
	var (
		err error
		ok  bool
	)
	fl := &TCPFingerListener{
		networkFamily: networkFamily,
		active:        wg,
		shuttingDown:  shuttingDown,
	}

	listener, err := net.Listen(fl.networkFamily, opts.listen)
	if err != nil {
		return nil, err
	}

	fl.tcpListener, ok = listener.(*net.TCPListener)
	if !ok {
		return nil, fmt.Errorf("listened in %q on %s but did not get a TCP listener (but instead a %T)",
			fl.networkFamily, opts.listen, listener)
	}

	//fl.Entry = logrus.NewEntry(logger).WithFields(logrus.Fields{
	fl.Entry = logger.WithFields(logrus.Fields{
		"family": fl.networkFamily,
		"accept": fl.tcpListener.Addr(),
		"pid":    os.Getpid(),
	})
	return fl, nil
}

// GoServeThenClose wraps the start-up of a listener; this handles spawning the
// go-routine; do not also wrap this in a go-routing other than the one which
// later listens on the active waitgroup.
func (fl *TCPFingerListener) GoServeThenClose() {
	fl.active.Add(1)
	fl.Info("listening")
	go fl.serveThenClose()
}

func (fl *TCPFingerListener) serveThenClose() {
	defer func() {
		if err := fl.tcpListener.Close(); err != nil {
			fl.WithError(err).Error("when closing listening socket")
		} else {
			fl.Info("closed listening socket")
		}
		fl.active.Done()
	}()

LOOP:
	for {
		select {
		case <-fl.shuttingDown:
			break LOOP
		default:
		}
		// If this _is_ overriden to 0, then shutdown via signal will not exit
		// until after a connection on each listening service.
		if opts.listenTime != 0 {
			fl.tcpListener.SetDeadline(time.Now().Add(opts.listenTime))
		}
		conn, err := fl.tcpListener.AcceptTCP()
		acceptedAt := time.Now()
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Timeout() {
				fl.Debug("expected timeout accepting connection")
				continue
			}
			fl.WithError(err).Error("accepting connection")
			continue
		}
		fl.active.Add(1)
		c := &TCPFingerConnection{
			// not sure that Entry is go-routine-safe, so spawn a new Entry
			// from the Logger for each go-routine
			Entry: fl.Entry.Logger.WithFields(logrus.Fields{
				"local":       conn.LocalAddr(),
				"remote":      conn.RemoteAddr(),
				"accept-time": acceptedAt,
			}),
			l:    fl,
			conn: conn,
		}
		go c.handleOneConnection()
	}

	return
}

func (c *TCPFingerConnection) handleOneConnection() {
	var written int64

	defer func() {
		err := c.conn.Close()
		if err != nil {
			c.WithError(err).Error("error when closing connection")
		}
		c.WithField("written", written).Info("connection closed")
		c.l.active.Done()
	}()

	c.Debug("accepted connection")
	// log-levels: nothing a remote person does warrants an error-level on our
	// part; we don't need to spam level-filtered logs with people being idiots
	// on the Internet.  So we log, with errors, but at Info level max.

	c.conn.SetReadDeadline(time.Now().Add(opts.requestReadTimeout))

	// Usually "one userid", with optional prefix, but can have a white-space separated list.
	// Let's limit to 500 octets.
	r := bufio.NewReaderSize(io.LimitReader(c.conn, 500), 501)
	input, err := r.ReadString('\n')
	if err != nil && err != io.EOF {
		c.WithError(err).Info("error reading request, aborting")
		return
	}
	l := len(input)
	if l < 1 {
		c.Info("read empty non-line, aborting")
		return
	}
	if input[l-1] != '\n' {
		c.Info("read unterminated request, perhaps over-long line, aborting")
		// we don't humour people sending abusive requests by trying to reply politely
		return
	}

	if l == 1 || l == 2 && input[0] == '\r' {
		c.Info("request to list local users, denying")
		written += c.sendLine("Local user listing denied.")
		return
	}
	c.crlf = true
	if input[l-2] == '\r' {
		input = input[:l-2]
	} else {
		c.crlf = false
		input = input[:l-1]
	}
	// nb: we stopped parsing at the first newline, so there might be an extra
	// CR in here, but that's the logging library's responsibility to escape if
	// needed.
	c.WithField("request", input).Info("received")

	seen := false
	c.long = false

	users := strings.Fields(input)
	if len(users) == 0 {
		c.Info("discarding request for being full of nothing")
		return
	}

	baseLog := c.Entry
	for _, user := range users {
		if user == "/w" || user == "/W" {
			c.long = true
			continue
		}
		if seen {
			written += c.sendLine("")
		}

		c.username = user
		c.uid = 0
		c.Entry = baseLog.WithField("username", user)
		// The Dispatch!
		written += c.processUser()
		c.Entry = baseLog
		c.uid = 0
		c.homeDir = ""
		c.username = ""

		seen = true

		if c.writeError {
			break
		}
	}
	if !seen {
		if c.long {
			c.Info("request to LONG list local users, denying")
			written += c.sendLine("Local user long listing denied.")
			return
		}
		c.Info("discarding strange request, please file bug-report to better classify & handle this")
		// still not rewarding hinkiness with attempts to write a response
		return
	}

	return
}
