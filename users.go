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

	"github.com/sirupsen/logrus"
)

type fingerUser struct {
	homeStat   os.FileInfo
	homeDir    string
	staticFile string
	uid        uint32
}

var invalidInUsername = "\000/\\"

// If you do crazy stuff with your OS, we'll try to cover that too.
func init() {
	if !strings.ContainsRune(invalidInUsername, filepath.Separator) {
		invalidInUsername += string(filepath.Separator)
	}
}

// We don't enumerate ahead of time: /home could be an automount
func findUser(username string, log logrus.FieldLogger) (fingerUser, bool) {

	// We want to reject not just outright requests for filenames, but also
	// attempts to break joining to `/home`, so `../etc/passwd`.  We thus reject
	// any `/` anywhere in the username.  Those can _only_ come from the alias
	// file lookup (or as part of homedir lookup from passwd).
	//
	// In Addition: although we're not testing against Windows at all, it'd be too
	// easy to miss this during a portability audit, so we're _also_ protecting
	// against `\` and we protect against both, on all platforms.
	//
	// ASCII NUL: we never invoke an external command, so all that matters is
	// whether or not path lookup would succeed.  A passwd lookup would stop at
	// that NUL, so be looking up something other than what we expected.  While
	// harmless in the absence of command execution, it's still fragile and I
	// don't like it, so we'll reject that too, explicitly, before going near
	// the FS.
	//
	// Heck, with a tiny init check, we can make sure that on platforms where
	// directory separator is not one of these, we're protected against those
	// too.
	if strings.ContainsAny(username, invalidInUsername) {
		return fingerUser{}, false
	}

	// Traditionally, we'd reject `@` to prevent remote host lookups, but
	// that's when invoking an external `finger` command.  We don't implement
	// remote host lookups, so don't need to prevent it.

	redirect := currentAliases()
	// pre-resolved, do not attempt to chase aliases-to-aliases

	// If upper-case characters are in the username on-disk, we'll only work if
	// the filesystem is case-insensitive.  If this bites you, please file a
	// bug report (which should include a good rationale if it's not a
	// pull-request for working code you're contributing ... and a decent
	// rationale even with a pull-request).
	username = strings.ToLower(username)

	if target, ok := redirect[username]; ok {
		if target[0] == '/' {
			return fingerUser{staticFile: target}, true
		}
		username = target
	}

	if opts.minPasswdUID != 0 {
		f, ok, authoritative := findUserByPasswd(username, log)
		if authoritative {
			return f, ok
		}
	}

	// TODO: implement lookup by GECOS name?

	if opts.homesDir != "" {
		candidate := filepath.Join(opts.homesDir, username)
		// users should not be able to rebind their home-dirs to be symlinks or whatever
		fi, err := os.Lstat(candidate)
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

	// We don't make 32 configurable or extracted because we use the concrete
	// type uint32 below.
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		log.WithError(err).Infof("error parsing passwd uid %q", u.Uid)
		return fingerUser{}, false, false
	}

	if uid64 < opts.minPasswdUID {
		return fingerUser{}, false, true
	}

	uid := uint32(uid64)

	// Here we do allow symlinks, if that's explicitly what's listed in /etc/passwd.
	// Ugh.
	fi, err := os.Stat(u.HomeDir)
	switch {
	case err != nil:
		log.WithError(err).Info("passwd user homedir won't stat")
		return fingerUser{}, false, false // consider for auth: opts.passwdHomedirOrBust ?
	case fi.IsDir():
		// We don't _directly_ care what the ownership of the dir is, passwd is
		// authoritative for what the ownership of the files within needs to
		// be.
		return fingerUser{
			homeDir:  u.HomeDir,
			uid:      uid,
			homeStat: fi,
		}, true, true
	}
	log.WithField("not-dir", u.HomeDir).WithField("mode", fi.Mode().String()).Warn("passwd user homedir not a directory")
	return fingerUser{}, false, false

}
