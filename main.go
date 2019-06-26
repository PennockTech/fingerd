// Copyright © 2016,2019 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

// We are canonically imported from go.pennock.tech/fingerd but because we are
// not a library, we do not apply this as an import constraint on the package
// declarations.  You can fork and build elsewhere more easily this way, while
// still getting dependencies without a dependency manager in play.
//
// This comment is just to let you know that the canonical import path is
// go.pennock.tech/fingerd and not now, nor ever, using DNS pointing to a
// code-hosting site not under our direct control.  We keep our options open,
// for moving where we keep the code publicly available.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
)

// I initially set 64 and in my first tests hit this because of an 84K .pubkey
// Let's be a _little_ more generous; 256KB by default let's one use send up to
// very slightly more than three-quarters of a MB.
const defaultFileSizeLimit = 256 * 1024

var opts struct {
	aliasfile           string
	listen              string
	homesDir            string
	runAsUser           string
	pidFile             string
	fileSizeLimit       int64
	requestReadTimeout  time.Duration
	requestWriteTimeout time.Duration
	minPasswdUID        uint64
	showVersion         bool
}

func init() {
	flag.StringVar(&opts.aliasfile, "alias-file", "/etc/finger.conf", "file to read aliases from (if it exists)")
	flag.StringVar(&opts.homesDir, "homes-dir", "/home", "where end-user home-dirs live")
	flag.StringVar(&opts.listen, "listen", ":79", "address-spec to listen for finger requests on")
	flag.StringVar(&opts.runAsUser, "run-as-user", "", "if starting as root, setuid to this user")
	flag.StringVar(&opts.pidFile, "pidfile", "", "write pid to this file after bind but before listening")
	flag.DurationVar(&opts.requestReadTimeout, "request.timeout.read", 10*time.Second, "timeout for receiving the finger request")
	flag.DurationVar(&opts.requestWriteTimeout, "request.timeout.write", 30*time.Second, "timeout for each write of the response")
	flag.Int64Var(&opts.fileSizeLimit, "file.size-limit", defaultFileSizeLimit, "how large a file we will serve")
	flag.Uint64Var(&opts.minPasswdUID, "passwd.min-uid", 0, "set non-zero to enable passwd lookups")
	flag.BoolVar(&opts.showVersion, "version", false, "show version and exit")

	// TODO: remove this in a future release
	var listenTime time.Duration
	flag.DurationVar(&listenTime, "listen.at-a-time", 0, "defunct and does nothing (will be removed in a future release)")
}

func main() {
	flag.Parse()

	if opts.showVersion {
		version()
		return
	}

	// q: should this really be one global waitgroup instead of per-AF and entirely encapsulate in the TCPFingerListener?
	running := &sync.WaitGroup{}
	running.Add(1)
	shutdown := make(chan struct{})

	logger := setupLogging()
	masterThreadLogger := logrus.NewEntry(logger).WithFields(logrus.Fields{
		"uid": os.Getuid(),
		"gid": os.Getgid(),
		"pid": os.Getpid(),
	})

	haveListeners := make([]*TCPFingerListener, 0, 3)

	if tmp, ok := inheritedListeners(running, shutdown, logger); ok {
		masterThreadLogger.Infof("recovered %d listeners", len(tmp))
		haveListeners = tmp
	} else {
		for _, netFamily := range []string{"tcp4", "tcp6"} {
			fl, err := NewTCPFingerListener(netFamily, running, shutdown, logger)
			if err != nil {
				// It's not an error to fail to listen on just one family (eg,
				// system which is missing IPv4) so only Warn level.  If we got
				// none at all, then we'll fatal out below, which will cover us.
				masterThreadLogger.WithError(err).Warnf("failed to listen/%s", netFamily)
			} else {
				haveListeners = append(haveListeners, fl)
				// start below, after dropping privs and loading aliases
			}
		}
	}

	running.Done()
	if len(haveListeners) == 0 {
		// avoid chewing CPU in a tight loop if we're being constantly respawned
		time.Sleep(time.Second)
		masterThreadLogger.Fatal("no listeners accepted; slept 1s before exiting")
	}

	if os.Getuid() == 0 {
		masterThreadLogger.Info("running as root, need to drop privileges")
		dropPrivileges(haveListeners, logger)
		// only reach here if something has gone wrong; dropPrivileges _should_ re-exec us
		time.Sleep(time.Second)
		masterThreadLogger.Fatal("we must drop privileges when running as root")
	}

	// Set up signal handling as soon as we've dropped privs, even though we'll
	// not act on it until late.
	ch := make(chan os.Signal)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT)

	// We parse these _after_ dropping privileges, so the listening socket is open, but
	// before we start the listening, so that the aliases are available without race.
	if opts.aliasfile != "" {
		// It's okay for the file to not exist.  Also, if it doesn't exist but later comes into existence,
		// we accept it at that point.  A _missing_ file should not immediately blank data (might be a race
		// between updates in a bad editor) so write an empty file first, before deleting it, if you want that.
		//
		// Because it's okay to not exist, we never actually fail setup and abort service.  If we lose
		// the ability to dynamically reload then that will be logged.  It's thus in the audit trail and
		// an acceptable degradation of service.
		loadMappingData(logger)
		scheduleAutoMappingDataReload(logger)
	}

	// Pidfile must be after bind, but before listening.
	var weCreatedPidfile bool
	if opts.pidFile != "" {
		pf, err := os.Create(opts.pidFile)
		if err != nil {
			masterThreadLogger.WithError(err).WithField("pidfile", opts.pidFile).Info("unable to create pidfile")
		} else {
			fmt.Fprintf(pf, "%d\n", os.Getpid())
			_ = pf.Close()
			weCreatedPidfile = true
		}
	}

	// From this point on, we're sufficiently init-like to pass muster.
	go childReaper(logger)

	// From this point on, we're accepting connection.
	for _, fl := range haveListeners {
		fl.GoServeThenClose()
	}

	masterThreadLogger.WithFields(logrus.Fields{
		"argv":      os.Args,
		"version":   currentVersion(),
		"listeners": len(haveListeners),
	}).Info("running")

	// Hang around forever, or until signalled
	masterThreadLogger.WithField("signal", <-ch).Warn("shutdown signal received")

	close(shutdown)
	running.Wait()

	if weCreatedPidfile {
		_ = os.Remove(opts.pidFile)
	}

	masterThreadLogger.Info("exiting cleanly")
	logrus.Exit(0)
}
