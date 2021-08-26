/*	$OpenBSD: log.c,v 1.1 2018/07/10 16:39:54 florian Exp $	*/

/*
 * Copyright (c) 2003, 2004 Henning Brauer <henning@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

#include "log.h"
#include "twind.h"

#define MAXLOGLINE 1024

static int		 debug;
static int		 verbose;
static int access_fd;
static int error_fd;

static const char	*log_procname;

void
log_init(int n_debug, int facility)
{
	extern char	*__progname;

	debug = n_debug;
	verbose = n_debug;
	log_procinit(__progname);

	if (!debug)
		openlog(__progname, LOG_PID | LOG_NDELAY, facility);

	tzset();
}

void
log_procinit(const char *procname)
{
	if (procname != NULL)
		log_procname = procname;
}

void
log_setverbose(int v)
{
	verbose = v;
}

int
log_getverbose(void)
{
	return (verbose);
}

void
logit(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	char	*nfmt;
	int	 saved_errno = errno;

	if (debug) {
		/* best effort in out of mem situations */
		if (asprintf(&nfmt, "%s\n", fmt) == -1) {
			vfprintf(stderr, fmt, ap);
			fprintf(stderr, "\n");
		} else {
			vfprintf(stderr, nfmt, ap);
			free(nfmt);
		}
		fflush(stderr);
	} else
		vsyslog(pri, fmt, ap);

	errno = saved_errno;
}

void
log_warn(const char *emsg, ...)
{
	char		*nfmt;
	va_list		 ap;
	int		 saved_errno = errno;

	/* best effort to even work in out of memory situations */
	if (emsg == NULL)
		logit(LOG_ERR, "%s", strerror(saved_errno));
	else {
		va_start(ap, emsg);

		if (asprintf(&nfmt, "%s: %s", emsg,
		    strerror(saved_errno)) == -1) {
			/* we tried it... */
			vlog(LOG_ERR, emsg, ap);
			logit(LOG_ERR, "%s", strerror(saved_errno));
		} else {
			vlog(LOG_ERR, nfmt, ap);
			free(nfmt);
		}
		va_end(ap);
	}

	errno = saved_errno;
}

void
log_warnx(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_ERR, emsg, ap);
	va_end(ap);
}

void
log_info(const char *emsg, ...)
{
	va_list	 ap;

	va_start(ap, emsg);
	vlog(LOG_INFO, emsg, ap);
	va_end(ap);
}

void
log_debug(const char *emsg, ...)
{
	va_list	 ap;

	if (verbose) {
		va_start(ap, emsg);
		vlog(LOG_DEBUG, emsg, ap);
		va_end(ap);
	}
}

static void
vfatalc(int code, const char *emsg, va_list ap)
{
	static char	s[BUFSIZ];
	const char	*sep;

	if (emsg != NULL) {
		(void)vsnprintf(s, sizeof(s), emsg, ap);
		sep = ": ";
	} else {
		s[0] = '\0';
		sep = "";
	}
	if (code)
		logit(LOG_CRIT, "fatal in %s: %s%s%s",
		    log_procname, s, sep, strerror(code));
	else
		logit(LOG_CRIT, "fatal in %s%s%s", log_procname, sep, s);
}

void
fatal(const char *emsg, ...)
{
	va_list	ap;

	va_start(ap, emsg);
	vfatalc(errno, emsg, ap);
	va_end(ap);
	exit(1);
}

void
fatalx(const char *emsg, ...)
{
	va_list	ap;

	va_start(ap, emsg);
	vfatalc(0, emsg, ap);
	va_end(ap);
	exit(1);
}

void
open_twind_logs(void)
{
	if ((access_fd = open(_PATH_TWIND_ACCESS_LOG, O_WRONLY|O_APPEND|O_CREAT, 0644))
		== -1)
		fatalx("Cannot open access log: %s", _PATH_TWIND_ACCESS_LOG);

	if ((error_fd = open(_PATH_TWIND_ERROR_LOG, O_WRONLY|O_APPEND|O_CREAT, 0644))
		== -1)
		fatalx("Cannot open error log: %s", _PATH_TWIND_ACCESS_LOG);

	log_debug("Log files open");
}

void
close_twind_logs(void)
{
	log_debug("Closing log file");
	close(access_fd);
	close(error_fd);
}

void
log_access(const struct client_connection *cc, const char *fmt, ...)
{
	char tmstr[29];
	struct tm tm;
	time_t t;

	t = time(NULL);
	tm = *localtime(&t);

	if (strftime(tmstr, sizeof(tmstr), "%d/%b/%Y:%H:%M:%S %Z", &tm) == 0) {
		log_warn("strftime couldn't save time string");
		return;
	}

	user_log(0, "%s - - [%s] %s", cc->client_addr, tmstr, fmt);
}

void
log_error(const struct client_connection *cc, const char *fmt, ...)
{
	char tmstr[29];
	struct tm tm;
	time_t t;

	t = time(NULL);
	tm = *localtime(&t);
	if (strftime(tmstr, sizeof(tmstr), "%d/%b/%Y:%H:%M:%S %Z", &tm) == 0) {
		log_warn("strftime couldn't save time string");
		return;
	}

	user_log(1, "[%s] [error] [client %s] %s", tmstr,
			cc->client_addr, fmt);
}

void
user_log(int target, const char *fmt, ...)
{
	va_list ap;
	int fd = -1;

	va_start(ap, fmt);
	if (target == 0)
		fd = access_fd;
	else if (target == 1)
		fd = error_fd;
	else {
		log_warn("Non-existent user log target");
		return;
	}

	vdprintf(fd, fmt, ap);
	dprintf(fd, "\n");

	va_end(ap);
}
