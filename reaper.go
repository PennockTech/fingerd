// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Sirupsen/logrus"
)

// We expect to be the only process running inside a jail/container, so we
// should reap all children, always ... just in case we're not.
func childReaper(log logrus.FieldLogger) {
	log = log.WithField("subsystem", "reaper")

	// We don't assume signals do not coalesce; we might get a SIGCHLD, we
	// might not.  Instead, we just swallow all SIGCHLD and we wait.
	// We wait including WUNTRACED so that if "something happens" with a child,
	// we at least log it, and WCONTINUED too.
	// If you see these in the logs and you have set up an isolated environment,
	// it's intrusion spoor.

	go func() {
		ch := make(chan os.Signal, 20)
		signal.Notify(ch, syscall.SIGCHLD)
		for {
			log.WithField("signal", <-ch).Info("signal received")
		}
	}()

	var status syscall.WaitStatus
	var rusage syscall.Rusage

	for {
		pid, err := syscall.Wait4(-1, &status, syscall.WUNTRACED|syscall.WCONTINUED, &rusage)
		if err != nil {
			switch err {
			case syscall.EINTR:
				continue
			case syscall.ECHILD:
				time.Sleep(time.Second)
				continue
			}
			log.WithError(err).Info("error from Wait4()")
			time.Sleep(250 * time.Millisecond)
			continue
		}
		l := log.WithField("pid", pid)
		if status.Exited() {
			l = l.WithField("exit-code", status.ExitStatus())
		}
		if status.CoreDump() {
			l = l.WithField("core-dumped", true)
		}
		if status.Signaled() {
			l = l.WithField("died-signal", status.Signal())
		}
		if status.Stopped() {
			l = l.WithField("stopped", status.StopSignal())
		}
		if status.Continued() {
			l = l.WithField("continued", true)
		}
		l.Info("child state")
	}
}
