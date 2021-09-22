# twind

twind is a simple daemon serving static files over the gemini protocol.  It is
intended to have as few knobs as possible and has no support for a
configuration file.  twind is named after the latin word for gemini - twins.

twind is known to run on OpenBSD, FreeBSD and Linux and currently supports

* Serving static gemini files
* Virtual hosts
* MIME handling
* IPv4 and IPv6 support

It doesn't support CGI handling and probably never will.  There are more
advanced gemini servers out there if you look for fancy stuff.

## Installation

twind is written in plain C and you need to have the following software
installed:

* A C compiler (tested with clang >= 11 and GCC >= 9)
* LibreSSL or OpenSSL
* POSIX compatible libc with pthreads support
* make (both BSD and GNU make will work)

twind needs a dedicated user called '_twind' and directory to run.  The
Makefile contains a command to create the user.  Note that you shall not change
the user's name and the directory twind needs!  By default, the user ID for
_twind is set to 4000.  If you need another user ID, change the UID variable
in the Makefile.

```
$ make
# make install
# make user
```

### TLS certificates

twind expects to find a X509 certificate and a corresponding private key
under the following locations (which cannot be changed):

* /etc/twind/twind.cert.pem
* /etc/twind/twind.key.pem

Either copy your existing keys to these locations or generate a new key and
certificate by using the Makefile.  Note that the command overwrites any existing
key without warning!  To generate both key and certificate use the following
command and provide the hostname via the HN variable.  If you don't provide the
hostname the command will fail!

```
# make setuptls HN=example.com
```

## Usage

twind has support for virtual hosts.  If your gemini server is called
example.com you have to create a dedicated sub directory under `/var/twind`:

```
# cd /var/twind
# mkdir example.com
# <copy files into the example.com directory>
```

In case your server is also reachable via gemini.example.com and you want to
serve the same content as on example.com you can create a symlink.  In case you
want to serve different content, you have to create a dedicated sub directory.

twind needs root permissions to start and will drop its privileges as soon as
possible.  It will also chroot to `/var/twind`.

```
# twind
```

For debugging purposes, you can start twind with -df option so that debugging
and running in the foreground is enabled.

## Contact

Please send feedback, patches by email to git()xosc.org.  Send git formatted
patches, see https://git-send-email.io/ for more information.
