// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/Sirupsen/logrus"
)

type fingerUser struct {
	homeStat   os.FileInfo
	homeDir    string
	staticFile string
	uid        uint32
}

// We don't enumerate ahead of time: /home could be an automount
func findUser(username string, log logrus.FieldLogger) (fingerUser, bool) {

	if strings.ContainsRune(username, '/') {
		return fingerUser{}, false
	}

	redirect := currentAliases()
	// pre-resolved, do not attempt to chase aliases-to-aliases

	// If upper-case characters are in the username on-disk, we'll only work if
	// the filesystem is case-insensitive.  If this bites you, please file a
	// bug report (which should include a good rationale if it's not a
	// pull-request for working code you're contributing).
	username = strings.ToLower(username)

	if target, ok := redirect[username]; ok {
		if target[0] == '/' {
			return fingerUser{staticFile: target}, true
		}
		username = target
	}

	if opts.minPasswdUid != 0 {
		f, ok, authoritative := findUserByPasswd(username, log)
		if authoritative {
			return f, ok
		}
	}

	// TODO: implement lookup by GECOS name?

	if opts.homesDir != "" {
		candidate := filepath.Join(opts.homesDir, username)
		// users should not be able to rebind their home-dirs to be symlinks or whatever
		fi, err := os.Stat(candidate)
		switch {
		case err != nil:
			// break out here if want other types of lookup even if homesDir is set
			return fingerUser{}, false
		case fi.IsDir():
			stat, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				log.WithField("dir", candidate).Warnf("bug in code for this platform: stat.Sys() not Stat_t but instead %T", fi.Sys())
				return fingerUser{}, false
			}
			return fingerUser{homeStat: fi, homeDir: candidate, uid: stat.Uid}, true
		default:
			return fingerUser{}, false
		}
	}

	return fingerUser{}, false
}

func findUserByPasswd(username string, log logrus.FieldLogger) (
	result fingerUser,
	ok bool,
	authoritative bool,
) {
	u, err := user.Lookup(username)
	if err != nil {
		return fingerUser{}, false, false
	}

	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		log.WithError(err).Infof("error parsing passwd uid %q", u.Uid)
		return fingerUser{}, false, false
	}

	if uid64 < opts.minPasswdUid {
		return fingerUser{}, false, true
	}

	uid := uint32(uid64)

	fi, err := os.Stat(u.HomeDir)
	switch {
	case err != nil:
		log.WithError(err).Info("passwd user homedir won't stat")
		return fingerUser{}, false, false // consider for auth: opts.passwdHomedirOrBust ?
	case fi.IsDir():
		// we don't care what the ownership of the dir is, passwd is authoritative
		return fingerUser{
			homeDir:  u.HomeDir,
			uid:      uid,
			homeStat: fi,
		}, true, true
	}
	log.WithField("not-dir", u.HomeDir).Warn("passwd user homedir not a directory")
	return fingerUser{}, false, false

}
