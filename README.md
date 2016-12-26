fingerd
=======

This is an implementation of the server-side of the finger protocol, per
[RFC742][].  This is written in Golang and is designed to be able to expect no
operating system services except the home directories of the users.

This can be deployed in an empty "jail" or "container" with a read-only
"nullfs mount" or "bind mount" providing access to the home directories.

This daemon will reap all children so that on platforms where the only process
in a container must act like init, it can be used as such an init; the daemon
does not fork but will collect and log the exit status of any other processes
which join the container and then exit.

We tend to reveal only the information deliberately exposed by a user and no
local system information.  For those, use a system-native finger daemon.  Our
use-case is exposure to the Internet for constrained information disclosure.

Because of this use-model, if a given user does not have any of the
information files (`~/.plan`, `~/.project`, `~/.pubkey`) then we interpret
this as equivalent to the presence of the file `~/.nofinger`.

### Filesystem access required:

1. Home directories
2. Optionally system user database (passwd) access; default is to just allow
   pattern-matching against `/home/*`
3. Optional pid-file writing
4. If need to support a hostname instead of an IP address for the syslog
   service, then whatever is needed to load hostnames data sources in your
   environment (`/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/hosts` are
   obvious choices).  If not logging to syslog, this will not be needed.
5. Reading `/etc/finger.conf` if it exists (alias file)

### Inbound network access required:

1. Port 79 (finger) or as overriden on command-line

### Outbound network access required:

1. Ability to send back packets on an inbound-established TCP session
2. Ability to talk to a remote syslog server, if so configured on the
   command-line.


[RFC742]: https://tools.ietf.org/html/rfc742 "RFC 742: NAME/FINGER"
