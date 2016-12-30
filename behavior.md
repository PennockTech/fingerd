Fingerd Behavior
================

[RFC742][] lays out:
* TCP on port 79
* CRLF line termination
* Single request "line"
* Server sends data and closes connection as soon as done
* Empty command-line gives a default response ("who is on, etc")
* Some switches showing the relationship between finger and original whois

FreeBSD fingerd supports but we reject:
* Running external programs
* Various bits of system accounting information (last login, mail status, etc)
* Home directory, shell, office phone number, etc.
* Messaging status (via tty writeability, what a blast from the past; `talk`
  users might want this added back but it requires utmp parsing to determine
  where logged in, which is a lot of system-specific non-portable binary
  parsing, so we decline).
* Forwarding connections to other hosts
  + Comes because by default it just invokes the local finger daemon
* Showing where email is forwarded to if `~/.forward` is present
* Dropping a leading `*` from the GECOS field (but the source asks "why?")
* Showing various extra pieces of information from GECOS assigning meanings to
  the comma-separated fields

FreeBSD fingerd supports and we preserve:
* Aliases in `/etc/finger.conf` of form `aliasname:loginname` one-per-line
* Splitting the line `" \t\r\n"` and fingering each in turn (RFC suggests as
  comma-separated); a blank line separates the output of each
* `/W` turning on `-l` mode for subsequent usernames
* GECOS:
  + **Not yet supported**: we only lookup by usercode and the alias-map, not
    by full-name, and we don't reveal the full-name, so we don't yet need
    GECOS support.  But if we were to add it ...
  + Split on `,`; we only take the first field, but we accept that it _is_ a
    field
  + A `&` is replaced by the usercode
* `~/.nofinger`
* These files, and captions, in order:
  1. `~/.project` "Project:"
  2. `~/.plan` "Plan:" else "No Plan."
  3. `~/.pubkey` "Public key:"
* If file contents short enough and no intermediate newlines, put on the same
  line of output as the caption, with a space inbetween.
  + Short enough: 80 - caption_length - 5; but caption without `:`,
    so `: ` and `\r\n` are 4 characters, so constraining to 79 total.

What we do:

1. Empty command-line says "Finger service is available for some users."
2. 8-bit clean and generally assume UTF-8; if the client can't handle that,
   it's their problem.
3. Absence of the project/plan/pubkey files is equivalent to presence of the
   `~/.nofinger` file
4. By default, only users in `/home` are allowed, thus automatically rejecting
   "system" users.  If passwd-usage is to be enabled, then the required
   command-line option is the one which sets a lower-bound on the uid to be
   used (and `0` means "passwd off", so root can not be fingered).
5. Any invalid user, including nofinger users, should be reported as:
     `finger: fred: no such user` or thereabouts


[RFC742]: https://tools.ietf.org/html/rfc742 "RFC 742: NAME/FINGER"
