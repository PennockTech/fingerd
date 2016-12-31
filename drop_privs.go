// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"net"
	"os"
	"os/user"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Sirupsen/logrus"
)

const envKeyFdPassing = "FINGERD_fdstatus"

// if we're running as root, we need to drop privileges and re-exec.
// if we can't drop to a user, log it and return, let the caller abort.
//
// PORTABILITY: we are only called if os.Getuid() returns 0; if that happens
// on a system where Uid/Gid are not representations of integers, then this
// is not portable to such a platform and should be split off to a file which
// uses platform-constraint build tags.  If os.Getuid() can never return 0 on
// such platforms, then this failing is irrelevant as we're never called.
//
// We do not fork/exec: we are supposed to be usable as the init of a process
// namespace and should persist with our original pid.
func dropPrivileges(tfls []*TCPFingerListener, bareLogger *logrus.Logger) {
	if opts.runAsUser == "" {
		bareLogger.Error("root drop privs: missing --run-as-user to drop privileges to")
		return
	}
	log := bareLogger.WithField("run-as-user", opts.runAsUser)

	var (
		uid, gid       int
		uidStr, gidStr string
		err            error
	)

	// if the run-as-user is num:num then avoid the system DB
	re := regexp.MustCompile(`^(-?\d+):(-?\d+)$`)
	matches := re.FindStringSubmatch(opts.runAsUser)
	if matches != nil {
		uidStr = matches[1]
		gidStr = matches[2]
	} else {
		runUser, err := user.Lookup(opts.runAsUser)
		if err != nil {
			log.WithError(err).Errorf("can't find info about --run-as-user=%q", opts.runAsUser)
			return
		}
		uidStr = runUser.Uid
		gidStr = runUser.Gid
	}

	log = log.WithField("uid-str", uidStr)
	uid, err = strconv.Atoi(uidStr)
	if err != nil {
		log.WithError(err).Errorf("parsing uid %q", uidStr)
		return
	}
	if uid == 0 {
		log.Error("no, you don't drop privileges from root to root, don't be so silly")
		return
	}
	log = log.WithField("uid", uid)
	log = log.WithField("gid-str", gidStr)
	gid, err = strconv.Atoi(gidStr)
	if err != nil {
		log.WithError(err).Errorf("parsing gid %q", gidStr)
		return
	}
	log = log.WithField("gid", gid)

	// Ensure that when we exec, it's done from the same OS thread where we've dropped privileges,
	// for Linux where setuid is per-thread (and Golang doesn't propagate it).
	runtime.LockOSThread()

	listeningFds := ""
	for i := range tfls {
		// This actually does a dup() and probably has FD_CLOEXEC cleared, but we lack a Golang guarantee that it's cleared.
		fd, err := tfls[i].tcpListener.File()
		if err != nil {
			log.WithError(err).Error("unable to get fd from listener (%s)", tfls[i].networkFamily)
			runtime.UnlockOSThread()
			return
		}

		listeningFds += tfls[i].networkFamily + ":" + strconv.Itoa(int(fd.Fd())) + "\n"

		// technically we want to mask out the FD_CLOEXEC value, but there are no examples of safely using F_GETFD in the Golang
		// source tree, they only ever just set to 0 for fork/exec handling of FD_CLOEXEC there, and we're so deep in the weeds
		// that we should just play safe. FD_CLOEXEC is the only FD flag I know of, so just set 0 each time.
		_, _, err1 := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd.Fd()), syscall.F_SETFD, 0)
		if err1 != 0 {
			log.Errorf("unable to clear FD_CLOEXEC on fd %d (%s)", fd.Fd(), tfls[i].networkFamily)
			runtime.UnlockOSThread()
			return
		}
	}
	if err := os.Setenv(envKeyFdPassing, listeningFds); err != nil {
		log.WithError(err).Error("unable to store listening FD info in environ for exec")
		runtime.UnlockOSThread()
		return
	}

	if err := syscall.Setgid(gid); err != nil {
		log.WithError(err).Errorf("Unable to setgid(%d)", gid)
		runtime.UnlockOSThread()
		return
	}
	if err := syscall.Setuid(uid); err != nil {
		log.WithError(err).Errorf("Unable to setuid(%d)", uid)
		runtime.UnlockOSThread()
		return
	}

	err = syscall.Exec(os.Args[0], os.Args, os.Environ())
	if err == nil {
		log.Error("we returned from exec() without erroring, WORLD-ON-FIRE")
	} else {
		log.WithError(err).Error("returned from exec(), this is bad")
	}
}

// return true if we've inherited FDs via re-exec and populated the list.
// return false if the caller should start things normally.
func inheritedListeners(
	wg *sync.WaitGroup,
	shuttingDown <-chan struct{},
	logger *logrus.Logger,
) (
	[]*TCPFingerListener,
	bool,
) {

	details, ok := os.LookupEnv(envKeyFdPassing)
	if !ok {
		return nil, false
	}
	_ = os.Unsetenv(envKeyFdPassing) // don't care if it fails, it's a nicety

	recoveryLogger := logrus.NewEntry(logger).WithField("env-var", envKeyFdPassing)

	tfls := make([]*TCPFingerListener, 0, 3)

	i := 0
	for _, line := range strings.Split(details, "\n") {
		if len(line) == 0 {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != 2 {
			recoveryLogger.Fatal("malformed variable, line not two colon fields")
		}

		i++

		fd, err := strconv.Atoi(fields[1])
		if err != nil {
			recoveryLogger.WithError(err).Fatalf("malformed listening file-descriptor entry %d", i)
		}

		f := os.NewFile(uintptr(fd), fields[0])
		listener, err := net.FileListener(f)
		if err != nil {
			recoveryLogger.WithError(err).Fatal("unable to make a net listener from fd entry %d", i)
		}
		tl, ok := listener.(*net.TCPListener)
		if !ok {
			recoveryLogger.Fatal("net listener from fd entry %d not a *net.TCPListener", i)
		}

		fl := &TCPFingerListener{
			networkFamily: fields[0],
			active:        wg,
			shuttingDown:  shuttingDown,
			tcpListener:   tl,
		}
		fl.Entry = logger.WithFields(logrus.Fields{
			"family": fl.networkFamily,
			"accept": fl.tcpListener.Addr(),
			"pid":    os.Getpid(),
		})
		tfls = append(tfls, fl)
	}

	return tfls, true
}
