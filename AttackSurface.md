Attack Surface
==============

## Network Binding and runtime user

This fingerd program listens on the network, accepting unfiltered TCP,
listening by default on a privileged port.

Normally the bind to a privileged port requires elevated privileges: in
Classic Unix, it requires root privilege.  On the Linux kernel, it requires
the `CAP_NET_BIND_SERVICE` privilege.

The code is written in Golang, a type-safe language; the `unsafe` package is
not used in our code, thus no buffer overflows are believed to be possible.

On Linux, the `setuid(2)` system-call only affects the calling thread; at time
of writing, Golang's runtime does not and can not reliably drop privileges
across all system threads.  If there were to be a code-injecting compromise
then presumably it would bypass the Go scheduler and cross-routine memory
access, so there is nothing that would keep that code from injecting code into
a thread which has not dropped privileges.

Because Linux is the dominant Unix today, while other current Unix OSes have,
or have proposals for, per-thread credentials, we assume this model.

We refuse to run as root.  Even though our programming model _should_ make
this significantly safer than root-running daemons written in some dominant
languages, we do not need that access for anything except binding the socket.

Thus we have four available approaches:

1. Run without privilege of any kind, on a non-standard port.  If providing a
   production finger service, then use IP packet translation to redirect the
   packets for port 79 to our port.

   For PF packet filtering this might look like this (replace `192.0.2.3`
   either with your own external IP or `127.0.0.1` if happy with that):

   ```
   rdr pass proto tcp from any to any port 79 -> 192.0.2.3 port 1079
   ```

   With a load-balancer, this is just a matter of mapping the external port 79
   to whatever port is used on the instances behind the load-balancer.

2. Run with sufficient privilege to bind a server on a privileged port, but no
   more.  Keep that privilege for the lifetime of the process; if there is a
   security hole, then the attacker gains the ability to bind a privileged
   port.  In the code-base, this is handled as "could bind the sockets, but
   are not root, so no further action taken, just keep running".

   ```console
   sudo setcap cap_net_bind_service=+ep /path/to/this/fingerd
   ```

   This requires a filesystem which is mounted to allow raising privilege;
   since we exist to avoid needing overly-privileged environments, this is a
   little ironic.

3. Start as root, bind the sockets, lock the go-routine to an OS thread, drop
   privilege for (at least) this thread, then re-exec the executable on disk
   from this lower privilege, passing in the listening sockets.

4. Run on an OS where `os.Getuid()` won't return 0 and we don't understand
   privilege; we are not programmers with experience developing on such a
   platform and so above and beyond the usual open-source disclaimers of
   warranty we note that it is particularly dangerous to assume that this code
   is safe on such a platform.  (I believe, but do not know, that Microsoft
   Windows is such a platform).  Patches welcome to improve safety on such
   platforms.

We:

1. Try to bind; if that fails, we exit.
2. Check if we're UID 0 (root); if we are, we try to re-exec to the specified
   (via flag) user; if that flag is not given, we exit.
3. Nothing else on this topic.


## Invoker

We must not be installed as a setuid program.  This is not double-checked (it
falls into the category of "our world is too utterly broken and we're not
checking everything").

We trust the invoking user.  If the invoking user is not root then we only
have access to what they had access to.  If the invoking user is root or
otherwise privileged, then they already had that privilege.

Our only approach to dropping privilege is that _if_ our runtime UID is 0
(root) then we re-exec after dropping uid.  The invoker specifies the user; if
they have the privilege to start a process which _can_ change to another user,
then they can do that anyway and there is no attack surface here.
(Explicitly: they control `argv[0]` and we `exec()` that, trusting it.)

If we are started with any capability model other than UID giving us access,
then no attempt is made to drop those privileges.  We assume, but do not
verify, that such privileges are only those required to bind sockets to
listening IP privileged ports.

Because we trust the invoking user, are not designed to be a setuid
executable, and only possibly re-exec ourselves, no process state cleanup is
performed.  Environment variable or other ulimit issues can cause us to fail
in many weird and various ways.  This is not part of our _surface_ on a
privilege boundary and is acceptable.

Filesystem files are accessed as our running user; if that user is privileged,
a malicious local user (see below) may configure fingerd to return sensitive
data to which they do not otherwise have access.  We must not run as a
privileged user.  Do not use setcap to grant this fingerd extra _file_ access.

## Network traffic

We speak a slightly unusual protocol which was specified in [RFC742][] in
the year 1977.  The core is simple but the interpretation of the requested
fields is under-specified.  One example provided in the RFC is using
comma-separated lists of users, but the practice of the BSD code examined was
to use whitespace-separated lists.

We do not assume that the requester is well-behaved.

We typically write more data than we read.

We work only on TCP and rely upon the three-way handshake to avoid becoming a
DoS reflector.  Any system configuration which causes TCP handshakes to not be
safe in this way is considered "beyond the scope of our problem-space".

We read data, parse it, and then write responses.  We do this read only once,
although it might be split into many reads across multiple packets if small
packets are used, or packets are fragmented.  We rely upon the coherent stream
of data presented to userland after reassembly.  We cap how much data we read
(to less than one "modern full-size non-jumbo" packet).  We then parse up to
the first newline character and ignore anything thereafter.  Thus no
newline-injection should be possible.

Each request before the first newline is whitespace separated but the contents
of each field must be assumed malicious until proven otherwise.  In
particular, directory separator characters should be prohibited.  Against
that, UTF-8 home-directories might as well be allowed.  `/home/观音` is as
valid as `/home/hera`.  We only block known directory separator characters,
`/` and `\`.  No escape-decoding is performed, so no other forms of the
directory separators are believed to be representable.  If a UTF-8
normalization layer within the file-system interprets a directory separator
out of an octet other than 0x2F then that's a file-system bug.

We disallow ASCII NUL in a username.  We do not treat `@` specially, as we
do not implement remote finger lookup so there's no reason to reject it.

We impose time-limits, as well as size limits, on this reading of data.

Although the protocol specifies CRLF line termination, if our request was only
LF terminated then we'll reply using only LF termination instead of CRLF.

We write data, with some time-limits upon success.  Failures to write should
error out cleanly.

Badly formed requests are logged and dropped without attempting to reply.  We
only write data back on the TCP connection if the request was well-behaved.
The protocol is sufficiently simple that this should not impose undue burden
on interoperability testing.

We do not fork per request, but instead use Go-routines to have one go-routine
per current request.  The Golang runtime is designed to scale with this model,
thus many concurrent connections may impose some overhead in terms of memory;
given enough Go-routines, conceivably our memory and CPU overhead might grow
to unreasonable levels, but this has not been quantified.

Our error response may reflect text back to the requester, providing for
emitting chosen text.  We are not HTTP, we serve plain text, there is no
cross-site scripting to be aware of, no tokens to steal with XSRF.  If modem
command sequences missing timers are still an issue on your network then you
have bigger problems.  So we choose to say "No such user 'foo'" in response to
'foo' from the requester.

## System information

The point of fingerd is to reveal information to unauthenticated remote
clients about local system users.  Historically this has included a lot of
information also used for social engineering or even just finding out if now
is a good time to be active.

This fingerd does not reveal any "system" information and only reveals a bare
minimum of data.  If aliases are defined and the alias is fingered, then the
alias is what is shown in the output, not even the system usercode.  Real
names are not shown.

This fingerd only reveals content from files in the user's home directory.  If
no relevant files exist, the user is assumed to be uninterested in fingerd
exposure and is therefore represented as non-existent.

The nature of this implementation is that it doesn't rely upon the user
database, or anything except the home directories in one place and a possible
alias file.  This is explicitly to allow running inside a jail or container
where this daemon is the only executable present and everything else is
read-only and restricted to only the user home-directories.

We enumerate which files may be accessed (in README.md) to ease writing of
mandatory access control security enforcement policies, should an
administrator wish.  If this fingerd requires access to any file not
explicitly documented, then that is a bug in our documentation (if not the
code) and bug-reports are accepted.

The configuration file (default `/etc/finger.conf`) allows aliases pointing to
aliases (so loops must be detected and broken) and allows aliases pointing to
files in the file-system.  As long as this configuration file can not be
written to by a less-trusted user than the invoker, this does not add to the
attack surface.  We do not check permissions on this file as this can not be
sanely evaluated in a world of ACLs to determine if "someone untrusted" can
write.  Just do not configure fingerd to use a configuration file which can be
tampered with.  We do not check ownership of files pointed to in this file
(but do impose the "must be a file" and size checks).

## Listing or enumeration of local users

We explicitly do not implement a way to enumerate known local users; the
requester must know (or be probing for) the username or an alias to expose.

_For future consideration: we might ratelimit requests, especially if for
unknown users._

This would not be resilient to a botnet distributing the enumeration so would
not be real security, but would be a reasonable extra step to slow-down bad
actors.  There would be added complexity in the rate-limit tracking and how
large that dataset is allowed to become.

Absence of the rate-limits is a fair criticism.

## Local users

A local user is not trusted.  They can choose what of _their_ data to return.
We can not stop them copying system files to which they have access, so they
can expose snapshots of such files.

The fingerd runtime user is distinct from the user whose data is being
returned.  If the fingerd runtime user can access files the local-user can
not, then a symlink of `.plan -> /etc/shadow` would result in sensitive
information disclosure.

Thus we refuse to run as root.  The runtime user should be unprivileged in
access.  Per-user files must be readable by our runtime user.  The user's home
directory must be accessible to our runtime user, but not necessarily
readable.

Eg, `-rwx--x--x` or `-rwxr-x--x` are probably good choices of home directory
permission; fingerd will `stat(2)` for the explicit paths in that directory
which it cares about, it will not `readdir()`, so we need permission to
traverse through the directory to access contents (execute bit) but not
permission to enumerate the directory's contents (read bit).

If there are other non-same-group users on the system who should not have any
access to the home directory, then other filesystem ACLs may prove useful in
granting explicit access to just the fingerd runtime user, per the access
rules stated above.  fingerd does not inspect how it has access to files, it
only tries to access the files, via `open(..., O_RDONLY)`, `stat(2)`, and
`fstat(2)`.

We impose limits upon the size of the data which we will return from any given
per-user file.  We do allow symlinks, but `fstat(2)` the opened
file-descriptor before reading, to ensure that the target file is owned by
the same user as owns the symlink and is a regular file.  The symlink owner
must be either the local user or root.

If we do not restrict to regular files, or ensure the same owner, then a
symlink might point to /dev/random and cause slow-downs and on many systems a
draining of the kernel's entropy pool.  Thus we do restrict to regular files.

Without using the user database, we determine the correct uid by the stat of
the entry in `/home`, so if `/home/phil` is owned by uid 1234 then any files
within that must be owned by 1234; we stat and check, but also fstat after
opening for reading but before reading, so that any symbolic links are
handled.

## Wire privacy

The [RFC742][] protocol does not provide for TLS or other link security which
must be negotiated per-connection within the connection.  Traffic sniffing can
see data.

All data is exposed to all remote users anyway, thus any user known to exist
could be retrieved, but that would normally show up in the logs.  Thus an
eavesdropper can see data without appearing in our audit logs, and determine
which users exist, even if that was not otherwise known.  With link security,
they could only see that information about "some user" was requested and the
size of the data.  If the list of users is known and static, then the size of
the data returned would likely reveal which user was fingered via a reverse
lookup table of size -> username.  So in the presence of a known list of
users, TLS would buy nothing.  What TLS would offer is for the existence of
users to be revealed to eavesdroppers.

If this is a concern, [RFC742][] service should not be used or such users
should not expose data for use via [RFC742][]; we support the `.nofinger` file
convention to aid in filtering, even if `.plan` is wanted for something else.

No clients are known to this author which currently support TLS for finger.
Should there be serious interest, we can add TLS support fairly easily; this
adds complexity to our attack surface but it is the same complexity in every
other TLS service provider and is likely an acceptable trade-off.

## Anything else?

We've considered the invoking user; the relationship to the user who is having
information retrieved; the network; the trustworthiness of the network both in
who is on the other end and who might be eavesdropping; what sensitive data
might be on the local system and how it can be prevented from being exposed.

Enumeration is addressed and rate-limits suggested as a possible improvement.

Bug-reports about missing semantic aspects of this attack surface summary are
welcome.

[RFC742]: https://tools.ietf.org/html/rfc742 "RFC 742: NAME/FINGER"
