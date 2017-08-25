// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"gopkg.in/fsnotify.v1"
)

// opts.aliasfile defaults to /etc/finger.conf
// The format is man-page specified on BSD; "#" for comments, nothing about blank lines;
// Unix tradition, expect a final newline
// all real lines are:
//    alias:(user|alias)
// but aliases are only permitted to be _forward_ references (which avoids loops, but is
// inverted from the usual sense).  Since we're implementing this file for compatibility,
// stick to that constraint.
// Also aliases can be fully-qualified filenames (start with a `/`) to point elsewhere.

var aliases struct {
	sync.RWMutex
	to map[string]string
}

func init() {
	aliases.to = make(map[string]string)
}

func currentAliases() map[string]string {
	aliases.RLock()
	defer aliases.RUnlock()
	return aliases.to
}

func loadMappingData(log logrus.FieldLogger) {
	log = log.WithField("file", opts.aliasfile)
	var err error
	fh, err := os.Open(opts.aliasfile)
	if err != nil {
		log.WithError(err).Info("unable to load aliases")
		return
	}
	defer fh.Close()

	concrete := make(map[string]string)

	unresolved := make([][2]string, 0, 100)

	// No size limit on the alias file, we "trust" it
	r := bufio.NewReader(fh)
	err = nil
	var line string
	for lineNum := 0; err != io.EOF; {
		line, err = r.ReadString('\n')
		if err != nil && err != io.EOF {
			log.WithError(err).Warn("problem reading config, aborting")
			return
		}
		lineNum++
		line = strings.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 || len(fields[0]) == 0 || len(fields[1]) == 0 || strings.ContainsRune(fields[0], '/') {
			log.WithField("line", lineNum).Warn("malformed line, skipping")
			continue
		}

		unresolved = append(unresolved, [2]string{fields[0], fields[1]})
	}

	for i := len(unresolved) - 1; i >= 0; i-- {
		from := strings.ToLower(unresolved[i][0])
		to := unresolved[i][1]
		if to[0] != '/' {
			to = strings.ToLower(to)
		}
		if _, ok := concrete[from]; ok {
			log.Warn("alias %q defined more than once, last one wins", from)
			continue
		}
		if chain, ok := concrete[to]; ok {
			concrete[from] = chain
		} else {
			concrete[from] = to
		}
	}

	aliases.Lock()
	aliases.to = concrete
	aliases.Unlock()
	log.WithField("alias-count", len(concrete)).Info("parsed aliases")
	return
}

// as long as the _directory_ exists, we'll detect a late file creation and handle it fine.
func scheduleAutoMappingDataReload(log logrus.FieldLogger) {
	log = log.WithField("subsystem", "fs-watcher")
	// originally mostly ripped straight from fsnotify.v1's NewWatcher example in the docs
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.WithError(err).Error("unable to start FS watcher, will not detect changes")
		// We continue on without aborting
		return
	}
	logrus.RegisterExitHandler(func() { _ = watcher.Close() })

	basename := filepath.Base(opts.aliasfile)
	dirname := filepath.Dir(opts.aliasfile)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					log.Warn("terminating config-watcher event dispatcher")
					return
				}
				l := log.WithField("event", event)
				switch filepath.Base(event.Name) {
				case basename:
					if event.Op&fsnotify.Write == fsnotify.Write {
						l.Info("modification detected")
						// The actual work!  (also in some other edge-cases just below)
						loadMappingData(log)
					} else if event.Op&fsnotify.Create == fsnotify.Create {
						// better late than never
						l.Info("creation detected (adding watch)")
						loadMappingData(log)
						watcher.Add(opts.aliasfile)
					} else if event.Op&fsnotify.Chmod == fsnotify.Chmod {
						// assume file created with 0 permissions then chmod'd more open, so our initial read might
						// have failed.  Should be harmless to re-read the file.  If it was chmod'd unreadable, we'll
						// error out cleanly.
						l.Info("chmod detected")
						loadMappingData(log)
					} else if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
						l.Info("gone, removing watch")
						watcher.Remove(opts.aliasfile)
					}
					// no other scenarios known
				case dirname:
					// usually ...
					// nothing to do; file creation will create an event named for the file, which we detect above for the file
					// which we care about; chmod ... we care less about.
					if event.Op&fsnotify.Remove == fsnotify.Remove || event.Op&fsnotify.Rename == fsnotify.Rename {
						l.Warn("directory of config file gone, nuking watcher, no notifications anymore")
						// duplicate close on shutdown is safe
						_ = watcher.Close()
						return
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					log.Warn("terminating config-watcher event dispatcher")
					return
				}
				log.WithError(err).Warn("error")
			}
		}
	}()

	count := 0
	for _, p := range []string{opts.aliasfile, dirname} {
		err = watcher.Add(p)
		if err != nil {
			log.WithError(err).WithField("file", p).Info("unable to start watching")
			// do not error out
		} else {
			count++
		}
	}

	if count == 0 {
		log.Warn("unable to set up any watches, terminating FS watcher, auto-reloading gone")
		_ = watcher.Close()
	}

	return
}
