// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"flag"
	"log/syslog"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

var logOpts struct {
	json         bool
	syslogRemote string
	syslogProto  string
	syslogTag    string
	noLocal      bool
}

func init() {
	flag.BoolVar(&logOpts.json, "log.json", false, "format logs into JSON")
	flag.BoolVar(&logOpts.noLocal, "log.no-local", false, "inhibit stdio logging, only use any log hooks (syslog)")
	flag.StringVar(&logOpts.syslogRemote, "log.syslog.address", "", "host:port to send logs to via syslog")
	// We can add more variants, such as "rfcFOO", if needed:
	flag.StringVar(&logOpts.syslogProto, "log.syslog.proto", "udp", "protocol to use; [udp, tcp]")
	flag.StringVar(&logOpts.syslogTag, "log.syslog.tag", "fingerd", "tag for syslog messages")
}

// setupLogging should be changed to add whatever remote logging you want;
// <https://github.com/sirupsen/logrus> lists a variety of supported hooks for
// remote logging, whether into corporate log services, cloud log services,
// chat services, email, error/exception aggregation services or whatever else.
//
// You can also use a remote service as the `.Out` field, if it's configured to
// provide an io.Writer interface instead of being set as a hook.
//
// Tune to taste in this file and it should just work.
//
// If logging can't be set-up, please assume that this is fatal and abort; we
// don't run without an audit trail going where it is supposed to go.
// If a network setup fails initial setup when called and returns an error,
// then so be it: we're a finger service, not critical plumbing infrastructure
// which must come up so that other things can come up.  Don't add complexity.
// (If it turns out that complexity is needed for one flaky setup, then and only
// then add it.)
//
// Recommend a sleep before Fatal so that if we keep dying, we don't die in a
// fast loop and chew system resources.
func setupLogging() *logrus.Logger {
	l := logrus.New()

	// other plugins available include "logstash", in case that's of interest
	// in your environment.
	if logOpts.json {
		l.Formatter = &logrus.JSONFormatter{}
	}

	// nb: looks like logrus_syslog as a hook is not filtering out ANSI color
	// escape sequences.  So probably best to just use with JSON.  Or tell me
	// what I'm doing wrong with logging setup.
	if logOpts.syslogRemote != "" {
		switch strings.ToLower(logOpts.syslogProto) {
		case "tcp", "udp":
			logOpts.syslogProto = strings.ToLower(logOpts.syslogProto)
		default:
			time.Sleep(time.Second)
			l.Fatalf("unknown syslog protocol %q", logOpts.syslogProto)
		}
		hook, err := logrus_syslog.NewSyslogHook(
			logOpts.syslogProto,
			logOpts.syslogRemote,
			syslog.LOG_DAEMON|syslog.LOG_INFO,
			logOpts.syslogTag)
		if err != nil {
			time.Sleep(time.Second)
			l.WithError(err).Fatal("unable to setup remote syslog")
		} else {
			l.Hooks.Add(hook)
		}
	}

	if logOpts.noLocal {
		f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err != nil {
			l.WithError(err).Error("unable to open system sink device")
		} else {
			l.Out = f
		}
	}

	return l
}
