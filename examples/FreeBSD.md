FreeBSD Setup
=============

Here is how a jailed finger service was set up on my system; ZFS pool is named
"zroot" (probably a poor choice, too late to change).

The goal: an "OS-less Jail"; no setuid binaries, no jail contents subject to
per-jail security updates other than the fingerd itself.

Compile `fingerd` as an unprivileged user, statically linking system
libraries:

```sh
go build -ldflags "-linkmode external -extldflags -static"
```

Then as root outside the Jails:

```sh
zfs create -o mountpoint=/jails zroot/jails
zfs create -o setuid=off -o utf8only=on -o atime=off -o devices=off zroot/jails/finger

mkdir /jails/finger/home
mkdir -p /jails/finger/srv/finger/bin
mkdir /jails/finger/etc
mkdir /jails/finger/log

vi /jails/finger/etc/finger.conf  # populate as desired

cp /path/to/compiled/fingerd /jails/finger/srv/finger/bin/./

zfs set readonly=on zroot/jails/finger

zfs create -o mountpoint=none \
           -o exec=off -o devices=off -o setuid=off \
           -o atime=off -o utf8only=on \
           zroot/logs
zfs create -o mountpoint=/jails/finger/log zroot/logs/finger

vi /etc/rc.conf     # see below

vi /etc/fstab
  # /jails/normal-user-jail/home  /jails/finger/home  nullfs  ro,late,noatime,noexec,nosuid  0  0

mount /jails/finger/home

vi /etc/jail.conf   # see below

service jail start finger

cp .../go.pennock.tech/fingerd/examples/freebsd-rc.d /path/to/my/rc.d/fingerd
chmod 755 /path/to/my/rc.d/fingerd

service fingerd start
```

Thus we mount the normal home-directories read-only into the finger Jail;
FreeBSD uses "nullfs" to do what Linux calls a "bind-mount".

In `/etc/rc.conf` I set `nullfs` as a network type so that mounts are deferred
until after ZFS mounts; I could also use `late` as a mount flag on recent
FreeBSD (and did in the example above) but since _all_ of my nullfs mounts are
for exposing content inside Jails, and the system is ZFS, I just re-order
nullfs mounts.


```
# this is part of /etc/rc.conf
local_startup="/path/to/my/rc.d $local_startup"
extra_netfs_types="nullfs"
fingerd_enable="YES"
```

Because `jail(8)` expects `/bin/sh` to exist inside the Jail, we can't start
the fingerd directly from there as normal; instead, we create a persistent
empty Jail, which we then reference.

```
# /etc/jail.conf
finger {
	ip4.addr = 192.0.2.1;
	# Want this but without 'sh' so instead we do "nothing" and persist
	# exec.start = "/srv/finger/bin/fingerd -run-as-user ....";
	# exec.system_jail_user;
	exec.start = "";
	exec.stop = "";
	persist;
	mount.nodevfs;
	mount.nofdescfs;
	allow.noset_hostname;
}
```

So we have a mostly empty ZFS filesystem, mounted read-only, nodev, nosuid;
we have a logs file-system which is also mounted noexec; we have access to
the home-directories via a read-only `nullfs` mount which also disables
execution; we have an empty Jail.

The [examples/freebsd-rc.d](./freebsd-rc.d) file, once deployed to
`/path/to/my/rc.d/fingerd`, then does the finger start-up from outside the
Jail.  (See below for a variation).

There is no rc system inside the Jail.  There is no shell.  While mounting via
`noexec` is not a strong security layer, when the only file-system mounted
which is not noexec has only one Golang binary, and is read-only, we're in a
stronger position.

If you allow more permissions by default for Jails, be sure to disable them
for the finger Jail.

The only slight issue is that the rc.d script relies upon an undocumented
aspect of the `rc.subr` processing in order to be able to control a process
inside a Jail.  By default, processing is careful to keep to "within this
$jid", so finding the pid of the daemon and confirming it is valid
double-checks the Jail too.  Thus our `JID=$(jls -j ${jail_name} jid)` line,
after sourcing the file, to override the JID and let the `status` and `stop`
commands work.

This deployment does use the "start as root, so can bind to port 79" approach
instead of redirecting.  Also note that we open the log-files from outside the
Jail.  This works well for FreeBSD where Jails provide _isolation_, not new
_namespaces_ for userids.  In a Linux container setup with user namespaces,
this would be an issue.

We have no user passwd system inside the Jail, so we are specifying the
uid:gid manually in this approach; note that FreeBSD has 32-bit uids but
`nobody` is `65534`, so on FreeBSD `-2:-2` is _not_ the correct specification.
We use `65534:65534`.

### A Variation

The file [freebsd-rc.d-1079](./freebsd-rc.d-1079) is almost the same as
[freebsd-rc.d](./freebsd-rc.d) but instead of starting as root and dropping to
a manually-specified nobody uid:gid, it instead switches to the `nobody` user
as defined _outside_ the Jail, and starts `fingerd` listening on port 1079.

You then use a packet-filter to set up port redirection; there are a number to
choose from.  I use PF, so the rule looks something like this:

```
# /etc/pf.conf
rdr_ifs="{ bce1, lo0 }"
#...
rdr on $rdr_ifs proto tcp from any to 192.0.2.3 port 79 -> 192.168.1.2 port 1079
```

In this example, the `$rdr_ifs` is a specification of the interfaces to
perform this redirection on; you don't need to include `lo0` if you only want to
redirect remote traffic, but without a VIMAGE kernel all traffic from jails on
this box itself will reach the jail via `lo0` so be sure to _not_ specify
`set skip on lo0`.

The documentation IP `192.0.2.3` is used to represent the public IP address;
the RFC1918 private address-space IP should be the same as the address in
`ip4.addr` in `/etc/jail.conf`.  Even before the OS-less approach, I used this
setup for my finger Jail.  The benefit is that if you do _not_ define `nat`
rules for the Jail, then traffic can get _in_ but nothing can get out.  If
there is a compromise, the attacker can only reach IP addresses on this one
box (other jails, the unjailed environment).  With a VIMAGE kernel with
per-Jail network stacks, this would be improved even further.

### Improvements to consider

Add support for `jail_attach(2)` logic to fingerd, to let it self-jail, such
that _nothing_ inside the jail needs to be mounted executable.

Use remote syslog writing (via `-log.syslog.address`), with `-log.no-local` to
prevent local logs, and don't set `-pidfile`, so that _nothing_ needs to be
writable from within the jail.

### Deploying Updates

Initial deploy documentation is inadequate without "how to deploy a routine
update" documentation.  How this fits into your environment is beyond the
scope of this example, but the core steps for a setup such as described here
boil down to:

```sh
# The unprivileged build user
cd ~/go/src/go.pennock.tech/fingerd
git pull
go build -ldflags "-linkmode external -extldflags -static"
```

And as root from outside the jails:

```sh
builddir=~builduser/go/src/go.pennock.tech/fingerd

zfs set readonly=off zroot/jails/finger
install -v $builddir/fingerd /jails/finger/srv/finger/bin/./
zfs set readonly=on zroot/jails/finger
service fingerd restart

service fingerd status
less /jails/finger/log/stderr
```

