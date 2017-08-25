fingerd
=======

`go get go.pennock.tech/fingerd`

This is an implementation of the server-side of the finger protocol, per
[RFC742][].  This is written in Golang and is designed to be able to expect no
operating system services except the home directories of the users.

This can be deployed in an empty "jail" or "container" with a read-only
"nullfs mount" or "bind mount" providing access to the home directories.

This daemon will reap all children so that on platforms where the only process
in a container must act like init, it can be used as such an init; the daemon
does not fork but will collect and log the exit status of any other processes
which join the container and then exit.  How well this works when running as
not-root has not been explored.

We tend to reveal only the information deliberately exposed by a user and no
local system information.  For those, use a system-native finger daemon.  Our
use-case is exposure to the Internet for constrained information disclosure.

Because of this use-model, if a given user does not have any of the
information files (`~/.plan`, `~/.project`, `~/.pubkey`) then we interpret
this as equivalent to the presence of the file `~/.nofinger`.

[An attack surfaces document][AttackSurface] is available.

Further choices [in our behaviour are documented](./behavior.md).

Access required is listed below; this list is supposed to be authoritative and
suitable for use in crafting a mandatory access control enforcement policy.

Note that although security was considered in the design of this server, it
was written as a holiday project without attention to tests or testability and
is thus not (yet) production grade.  "It mostly works for me."

No metrics are exported, only logs.


### Filesystem access required:

1. Home directories
2. Optionally system user database (passwd) access; default is to just allow
   pattern-matching against `/home/*`.  Also required for `-run-as-user` when
   starting as root (see a point below).
3. Optional pid-file writing; logs on stderr output redirection location
4. If need to support a hostname instead of an IP address for the syslog
   service, then whatever is needed to load hostnames data sources in your
   environment (`/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/hosts` are
   obvious choices).  If not logging to syslog, this will not be needed.
5. Reading `/etc/finger.conf` if it exists (alias file)
6. `/etc` itself, to set up a watch for re-emergence of `/etc/finger.conf`
   + This access and that of `/etc/finger.conf` can be disabled by setting
     `-alias-file=""`
7. If started as root, then the process needs access to re-exec itself once it
   has dropped privileges.  The file-system where this program is stored thus
   needs to be mounted to permit exec; this the only location which should
   permit exec.  The filesystem should be mounted `nosuid` _unless_ you choose
   to use setcap instead of a packet filter.  Please use a packet filter
   instead.

### Inbound network access required:

1. Port 79 (finger) or as overridden on command-line
  * Recommend using a non-standard port and starting as an unprivileged user,
    with a packet filter providing redirection.  See [AttackSurface][] for
    more details.

### Outbound network access required:

1. Ability to send back packets on an inbound-established TCP session
2. Ability to talk to a remote syslog server, if so configured on the
   command-line.

### Customization

The most likely need for code customization is to change where logs go; we use the
[logrus][] library which has a broad selection of plugins available to change
formatting and destinations; edit `logging_setup.go` to add support for
whatever is of local interest to you.

## Installation

```console
$ mkdir ~/go
$ export GOPATH="$HOME/go"
$ go get go.pennock.tech/fingerd
```

With those install steps, the binary can be found in `~/go/bin/fingerd`.
The `go get` command will fetch this repo, any dependent repos and perform the
build.

To build as a static binary for deployment into a lib-less environment:

```sh
go build -ldflags "-linkmode external -extldflags -static"
```

## Invoking

Invoke with `-help` to see help output listing known flags and defaults.

If starting as root, dropping to nobody, redirecting logs to someplace, and
all the users are in `/home/*`:

```sh
/srv/fingerd -run-as-user=nobody 2>/logs/fingerd
```

If starting as root, avoiding using the system user database ("passwd"),
logging remotely in JSON format to a log-host whose IP is known (avoid DNS)
and starting as `nobody`, relying upon that being uid `-2`, then:

```sh
/srv/fingerd -run-as-user=-2:-2 -log.json -log.no-local -log.syslog.address=192.0.2.2:514
```

If starting as non-root, so we won't drop privileges, but you want to listen
on port 1079 (unprivileged) to which packet-filter or loadbalancer rules will
redirect port 79 traffic, then:

```sh
/srv/fingerd -listen=:1079
```

The same, but also disabling use of `/etc/finger.conf` (a BSD convention) so
that you don't get attempts to watch for the file existing later, and using
MacOS:

```sh
/srv/fingerd -listen=:1079 -alias-file="" -homes-dir=/Users
```

Enable passwd lookup and disable "exists in /home so is a user" check:

```sh
/srv/fingerd -listen=:1079 -passwd.min-uid=500 -homes-dir=""
```

## Deployment examples

There is [FreeBSD](./examples/FreeBSD.md) documentation, describing setup
within an OS-less Jail.  An `rc.d` script is included.


[RFC742]: https://tools.ietf.org/html/rfc742 "RFC 742: NAME/FINGER"
[AttackSurface]: ./AttackSurface.md
[logrus]: https://github.com/sirupsen/logrus "logrus: Structured, pluggable logging for Go"
