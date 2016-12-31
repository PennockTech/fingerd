// Copyright © 2016 Pennock Tech, LLC.
// All rights reserved, except as granted under license.
// Licensed per file LICENSE.txt

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// text should not include the newline
func (c *TCPFingerConnection) sendLine(text string) (written int64) {
	pad := 2
	if !c.crlf {
		pad = 1
	}
	l := len(text)
	b := make([]byte, l+pad)
	copy(b, text)
	if c.crlf {
		b[l] = '\r'
		b[l+1] = '\n'
	} else {
		b[l] = '\n'
	}

	c.conn.SetWriteDeadline(time.Now().Add(opts.requestWriteTimeout))
	// stdlib net/fd_unix.go (*netFD).Write() handles short writes for us
	n, err := c.conn.Write(b)
	if err != nil {
		c.WithError(err).WithField("wrote", n).Info("write error")
		c.writeError = true
	}
	return int64(n)
}

func (c *TCPFingerConnection) sendOops(prefix string) (written int64) {
	if prefix != "" {
		return c.sendLine(fmt.Sprintf("%s: %s", prefix, "oops"))
	}
	return c.sendLine("oops")
}

func (c *TCPFingerConnection) processUser() (written int64) {
	// don't vary the output in different scenarios:
	var noSuchUserText = fmt.Sprintf("%q: no such user", c.username)

	u, ok := findUser(c.username, c.Entry)
	if !ok {
		// caller has already set up logging context to include username= field
		c.Info("unknown user")
		return c.sendLine(noSuchUserText)
	}

	// Static files as returned from aliases bypass "owner" checks
	if u.staticFile != "" {
		return c.sendFile(u.staticFile, "")
	}

	// let sendFile apply ownership checks (symlink attacks, etc)
	// (if u.uid not set, that just means no ownership checks)
	c.uid = u.uid

	c.homeDir = u.homeDir

	if c.homeFileStat(".nofinger") != nil {
		c.Info("user denies existence (.nofinger)")
		return c.sendLine(noSuchUserText)
	}

	haveProject := c.homeFileStat(".project")
	havePlan := c.homeFileStat(".plan")
	havePubkey := c.homeFileStat(".pubkey")
	if !(havePlan != nil || haveProject != nil || havePubkey != nil) {
		c.Info("user missing finger files, denying existence")
		return c.sendLine(noSuchUserText)
	}

	// We now decree that the user does exist.

	written += c.sendLine(fmt.Sprintf("User: %s", c.username))
	if c.writeError {
		return
	}

	if haveProject != nil && c.homeFileValid(haveProject) {
		written += c.sendFile(".project", "Project")
		if c.writeError {
			return
		}
	}
	if havePlan != nil && c.homeFileValid(havePlan) {
		written += c.sendFile(".plan", "Plan")
	} else {
		written += c.sendLine("No Plan.")
	}
	if c.writeError {
		return
	}
	if havePubkey != nil && c.homeFileValid(havePubkey) {
		written += c.sendFile(".pubkey", "Public key")
		if c.writeError {
			return
		}
	}

	return
}

func (c *TCPFingerConnection) homeFileStat(filename string) os.FileInfo {
	pathname := filepath.Join(c.homeDir, filename)
	fi, err := os.Stat(pathname)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return nil
		}
		c.WithError(err).WithField("filename", filename).Info("unusual stat failure")
		return nil
	}
	return fi
}

func (c *TCPFingerConnection) homeFileValid(fi os.FileInfo) bool {
	if fi.Size() == 0 {
		return false
	}
	switch fi.Mode() & os.ModeType {
	case 0, os.ModeSymlink:
		break
	default:
		return false
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		c.WithField("filename", fi.Name()).Warnf("bug in code for platform: stat.Sys() not Stat_t but instead %T", fi.Sys())
		return false
	}
	// here we do allow root-owned _symlinks_ ... I guess
	if stat.Uid != 0 && stat.Uid != c.uid {
		return false
	}
	return true
}

// sendFile returns either the amount written _or_ that nothing was written; if nothing
// was written, we treat it as not a problem as long as it's a permissions issue
func (c *TCPFingerConnection) sendFile(filename, prefix string) (written int64) {
	if c.homeDir != "" && !filepath.IsAbs(filename) {
		filename = filepath.Join(c.homeDir, filename)
	}
	// We expect the existence of the file to have already been established.
	// So this should be rare; there's a risk via race if the user
	f, err := os.Open(filename)
	log := c.WithField("file", filename)
	if err != nil {
		if os.IsPermission(err) {
			log.Info("permission denied, pretending non-existent")
			return 0
		}
		log.WithError(err).Warn("can't open to send")
		return c.sendOops(prefix)
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.WithError(err).Warn("can't stat open file-descriptor")
		return c.sendOops(prefix)
	}

	if fi.Size() == 0 {
		log.Info("pretending non-existent because file empty")
		return 0
	}

	if fi.Size() > opts.fileSizeLimit {
		log.Infof("pretending non-existent because file too large (%d > %d)", fi.Size(), opts.fileSizeLimit)
		return 0
	}

	if fi.Mode()&os.ModeType != 0 {
		log.Infof("pretending non-existent because not a file but instead: %s", fi.Mode().String()[0])
		return 0
	}

	// c.uid set non-zero when we have an expected-user-owner
	if c.uid != 0 {
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			log.Warnf("pretending non-existent because bug in code for platform: stat.Sys() not Stat_t but instead %T", fi.Sys())
			return 0
		}
		if stat.Uid != c.uid {
			log.Warnf("LOCAL USER ATTACK; pretending non-existent because owned %d but expected %d", stat.Uid, c.uid)
			return 0
		}
	}

	// should be done with safety checks, go ahead and send

	eolMarker := []byte{'\r', '\n'}
	if !c.crlf {
		eolMarker = eolMarker[1:]
	}

	// we know it's presented to us as a regular file, and the size is "not too
	// large", at time of stat, but the file could be open for writing
	// concurrently, so we _still_ want to use a LimitReader.  This will also
	// protect against virtual file-systems which get sizes wrong, etc etc.
	b := bufio.NewReaderSize(io.LimitReader(f, opts.fileSizeLimit), int(opts.fileSizeLimit+1))

	// Page things into memory from disk before we set network write deadlines
	// (while we're at it, if it's short enough, check for a newline in the first
	//  line, for prefix-joining)
	embeddedNewline := true
	func() {
		if fi.Size() > 80 {
			_, _ = b.Peek(int(fi.Size()))
			return
		}
		peekAhead, _ := b.Peek(int(fi.Size()))
		if !bytes.ContainsRune(peekAhead, '\n') {
			embeddedNewline = false
		} else if bytes.IndexRune(peekAhead, '\n') == int(fi.Size()-1) {
			embeddedNewline = false
		}
	}()

	// One deadline per file contents; we'll reset between multiple files
	// for each user, as that strictly bounds how much a user can extend the
	// timeout, but we don't want to deal with a slowloris reader.
	c.conn.SetWriteDeadline(time.Now().Add(opts.requestWriteTimeout))

	if prefix != "" {
		// If the caption/prefix is short enough, we put it on one line.
		// We choose (see behavior.md) to match FreeBSD's fingerd here:
		// 80 - caption_length - 5; but caption there without `:`
		l := len(prefix)
		buf := make([]byte, l+3)
		copy(buf, prefix)
		buf[l] = ':'
		l++
		if int(fi.Size()) < (75-l) && !embeddedNewline {
			buf[l] = ' '
			buf = buf[:l+1]
		} else if c.crlf {
			buf[l] = '\r'
			buf[l+1] = '\n'
		} else {
			buf[l] = '\n'
			buf = buf[:l+1]
		}

		n, err := c.conn.Write(buf)
		written += int64(n)

		if err != nil {
			log.WithError(err).Info("error writing prefix")
			c.writeError = true
			c.conn.SetWriteDeadline(time.Time{})
			return written
		}
	}

	for {
		// ReadLine's API doesn't indicate missing final newline but that's fine,
		// because we want to send one even if it's missing from the file.  So it's
		// "a low-level line-reading primitive. Most callers should [...]" but we're
		// in the group for whom this is the right choice, I think.
		chunk, isPrefix, err := b.ReadLine()
		// "ReadLine either returns a non-nil line or it returns an error,
		// never both." -- exception to normal Golang rule to check for content
		// before handling an error.
		if err != nil {
			if err == io.EOF {
				break
			}
			log.WithError(err).Info("encountered error while reading")
			break
		}
		n, err := c.conn.Write(chunk)
		written += int64(n)
		if err != nil {
			log.WithError(err).Infof("error returning file (wrote %d)", written)
			c.writeError = true
			break
		}
		if !isPrefix {
			n, err = c.conn.Write(eolMarker)
			written += int64(n)
			if err != nil {
				log.WithError(err).Infof("error returning file (wrote %d)", written)
				c.writeError = true
				break
			}
		}
	}

	c.conn.SetWriteDeadline(time.Time{})

	return written
}
