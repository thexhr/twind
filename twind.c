/*
 * Copyright (c) 2021 Matthias Schmidt <xhr@giessen.ccc.de>
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

#include <sys/file.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/in.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) &&\
	!defined(__DragonFly__)
#include <grp.h>
#endif /* __BSD__ */

#include "log.h"
#include "twind.h"

#define PID_BUF_SIZE 100
#define TWIND_USER "_twind"
#define _PATH_TWIND_CHROOT "/var/twind"
#define _PATH_TWIND_LOGS "/var/twind/logs"
#define _PATH_TWIND_CERT "/etc/twind/twind.cert.pem"
#define _PATH_TWIND_KEY "/etc/twind/twind.key.pem"
#define _PATH_TWIND_PID_CHROOT "/var/twind/twind.pid"
#define _PATH_TWIND_PID "twind.pid"

static void organize_termination(void);
static void open_sockets(int[2], int);
void *get_in_addr(struct sockaddr *);
void* main_request_handler(void*);
int receive_gemini_request(SSL*, char *);
int handle_incoming_connections(int, int, SSL_CTX *);
void fork_main_process(int[2], SSL_CTX *);
SSL_CTX* initialize_tls_context(void);
int open_pid_file(void);
static void drop_root(void);

#if !defined(__FreeBSD__) && !defined(__OpenBSD__) && !defined(__NetBSD__) &&\
	!defined(__DragonFly__)
void setproctitle(const char *, ...);
void setproctitle(const char *fmt, ...) {}
#endif /* __BSD__ */

static void
usage(void)
{
	extern char *__progname;

	fprintf(stderr, "usage: %s [-dfv] [-p port]\n", __progname);
	exit(-1);
}

static void
signal_handler(int signal)
{
	switch (signal) {
		case SIGINT:
		case SIGTERM:
			organize_termination();
			break;
		default:
			fatalx("Unknown signal");
	}
}

int
main(int argc, char *argv[])
{
	SSL_CTX *sslctx = NULL;
	int ch, fg_flag = 0, debug_flag = 0, verbose_flag = 0;
	int tcpsock[2] = { -1, -1 }, port = 1965;

	log_init(1, LOG_DAEMON);        /* Log to stderr until daemonized. */
	log_setverbose(1);

	while ((ch = getopt(argc, argv, "dfp:vV")) != -1) {
		switch(ch) {
			case 'd':
				debug_flag = 1;
				break;
			case 'f':
				fg_flag = 1;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'v':
				verbose_flag = 1;
				break;
			case 'V':
				fprintf(stderr, "Version %s\n", VERSION);
				exit(-1);
			default:
				usage();
				break;
		}
	}

	argc -= optind;
	argv += optind;

	if (geteuid())
		fatalx("need root privileges");

	open_pid_file();

	if (signal(SIGINT, signal_handler) == SIG_ERR)
		fatalx("signal");
	if (signal(SIGTERM, signal_handler) == SIG_ERR)
		fatalx("signal");

	open_sockets(tcpsock, port);

	sslctx = initialize_tls_context();

	drop_root();

	log_init(debug_flag, LOG_DAEMON);
	log_setverbose(verbose_flag);

	open_twind_logs();

#ifdef __OpenBSD__
	if (pledge("stdio inet dns proc rpath", NULL) == -1)
		fatalx("pledge");
#endif /* __OpenBSD__ */

	fork_main_process(tcpsock, sslctx);

	if (!fg_flag)
		if (daemon(0, 0) == -1)
			fatalx("daemonizing failed");

	organize_termination();

	return 0;
}

static void
organize_termination(void)
{
	pid_t sub_pid;

	log_debug("waiting for sub processes to terminate");
	for (;;) {
		sub_pid = wait(NULL);
		if (sub_pid == -1) {
			if (errno == ECHILD) {
				/* All sub processes are terminated */
				close_twind_logs();
				log_debug("twind turns to dust");
				exit(0);
			} else {
				fatalx("wait");
			}
		}
	}
}

SSL_CTX*
initialize_tls_context(void)
{
	SSL_CTX *sslctx;

	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	sslctx = SSL_CTX_new(TLS_method());
	if (sslctx == NULL)
		fatalx("Cannot initialize TLS CTX structure");

	SSL_CTX_set_ecdh_auto(sslctx, 1);

	/* Gemini requires TLSv1.2 minimum */
	if (SSL_CTX_set_min_proto_version(sslctx, TLS1_2_VERSION) != 1)
		fatalx("Cannot set minimum TLS version");

	if (SSL_CTX_use_certificate_file(sslctx, _PATH_TWIND_CERT, SSL_FILETYPE_PEM)
		!= 1)
		fatalx("Cannot load TLS certificate %s", _PATH_TWIND_CERT);

	if (SSL_CTX_use_PrivateKey_file(sslctx, _PATH_TWIND_KEY, SSL_FILETYPE_PEM)
		!= 1)
		fatalx("Cannot load TLS private key %s", _PATH_TWIND_KEY);

	return sslctx;
}

void *
get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return &(((struct sockaddr_in*)sa)->sin_addr);

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int
handle_incoming_connections(int counter, int tcpsock, SSL_CTX *sslctx)
{
	struct sockaddr_storage addr;
	struct client_connection *cc;
	char str[INET6_ADDRSTRLEN];
	pthread_t thread_id;
	socklen_t len = sizeof(addr);
	int ret, ssl_err;

#ifdef __OpenBSD__
	/* We can get rid of proc pledge here */
	if (pledge("stdio inet dns rpath", NULL) == -1)
		fatalx("pledge");
#endif /* __OpenBSD__ */

	memset(str, 0, sizeof(str));

	while (1) {
		ret = accept(tcpsock, (struct sockaddr *)&addr, &len);
		if (ret < 0)
			fatalx("Error when accepting connection");

		cc = xmalloc(sizeof(struct client_connection));

		inet_ntop(addr.ss_family, get_in_addr((struct sockaddr *)&addr), str, sizeof(str));
		strlcpy(cc->client_addr, str, INET6_ADDRSTRLEN);
		log_info("Connection from %s", cc->client_addr);

		if ((cc->ssl_peer = SSL_new(sslctx)) == NULL) {
			log_warn("Creating new TLS structure failed");
			free(cc);
			close(ret);
			continue;
		}

		if (SSL_set_fd(cc->ssl_peer, ret) == 0) {
			log_warn("TLS cannot set file descriptor");
			SSL_free(cc->ssl_peer);
			free(cc);
			close(ret);
			continue;
		}

		ssl_err = SSL_accept(cc->ssl_peer);
		if (ssl_err < 0) {
			ERR_print_errors_fp(stderr);
			log_warn("Fatal TLS error. Cannot accept TLS connection");
			SSL_shutdown(cc->ssl_peer);
			SSL_free(cc->ssl_peer);
			free(cc);
			close(ret);
			continue;
		} else if (ssl_err == 0) {
			log_warn("TLS handshake not successful");
			SSL_shutdown(cc->ssl_peer);
			SSL_free(cc->ssl_peer);
			free(cc);
			close(ret);
			continue;
		}

		log_debug("SSL connection using %s", SSL_get_cipher(cc->ssl_peer));

		if (pthread_create(&thread_id, NULL, main_request_handler, ((void*)cc))
			!= 0) {
			log_warn("Cannot create handling thread");
			SSL_shutdown(cc->ssl_peer);
			SSL_free(cc->ssl_peer);
			free(cc);
			close(ret);
			continue;
		}

		if (pthread_join(thread_id, NULL) != 0) {
			log_warn("Error while joining thread");
			SSL_shutdown(cc->ssl_peer);
			SSL_free(cc->ssl_peer);
			free(cc);
			close(ret);
			continue;
		}

		SSL_shutdown(cc->ssl_peer);
		SSL_free(cc->ssl_peer);
		free(cc);
		close(ret);
	}

	return 0;
}

void
fork_main_process(int tcpsock[2], SSL_CTX *sslctx)
{
	pid_t pid;
	int i;

	/* Fork two main handler processes, one for IPv4, one for IPv6 */
	for (i=0; i < 2; i++) {
		if (tcpsock[i] == -1)
			continue;
		switch (pid = fork()) {
			case -1:
				fatalx("Cannot fork() main IPv%d handler process", i == 0 ? 4 : 6);
			case 0:
				log_debug("Main IPv%d handling process started: %d", i == 0 ? 4 : 6,
					getpid());
				setproctitle("v%d %s", i == 0 ? 4 : 6, "handler");
				handle_incoming_connections(i, tcpsock[i], sslctx);
				exit(0);
		}
	}
}

void *
main_request_handler(void *argp)
{
	struct client_connection *cc = (struct client_connection *)argp;
	char finalpath[MAXREQLEN];
	char temp[MAXREQLEN];
	char request[MAXREQLEN];
	char *ext = NULL;
	char *mime = NULL;
	int ret;

	memset(finalpath, 0, sizeof(finalpath));
	memset(request, 0, sizeof(request));
	memset(temp, 0, sizeof(temp));

	if (receive_gemini_request(cc->ssl_peer, request) < 0) {
		log_warn("Receiving initial request failed");
		return NULL;
	}

	ret = get_path_from_request(request, finalpath);
	if (ret == -1) { /* Malformed request */
		log_error(cc, "Malformed request");
		send_non_success_response(cc->ssl_peer, STATUS_BAD_REQUEST);
		return NULL;
	} else if (ret == -2) { /* 404 */
		log_error(cc, "Request file not found");
		send_non_success_response(cc->ssl_peer, STATUS_NOT_FOUND);
		return NULL;
	}

	if ((ext = get_file_extension(finalpath)) == NULL) {
		log_debug("Cannot get file extension from %s", finalpath);
	} else {
		if ((mime = get_mime_type(ext)) == NULL)
			log_debug("Cannot get MIME type for %s", ext);
	}

	//user_log(0, "%s", finalpath);
	log_access(cc, finalpath);

	if (send_response(cc->ssl_peer, STATUS_SUCCESS, finalpath, mime) < 0) {
		log_warn("Sending response to client failed");
		return NULL;
	}

	free(ext);
	free(mime);

	return NULL;
}

/*
 * Gemini requests are a single CRLF-terminated line with the following structure:
 *
 * <URL><CR><LF>
 *
 * <URL> is a UTF-8 encoded absolute URL, including a scheme, of maximum length
 * 1024 bytes.
 */
int
receive_gemini_request(SSL *ssl_peer, char* request_buf)
{
	if (SSL_read(ssl_peer, request_buf, MAXREQLEN) <= 0)
		return -1;

	return 0;
}

static void
open_sockets(int tcpsock[2], int port)
{
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	socklen_t len;
	int opt = 1;

	memset(&addr4, 0, sizeof(addr4));
	addr4.sin_family = AF_INET;
	addr4.sin_port = htons(port);
	addr4.sin_addr.s_addr = INADDR_ANY;
	addr = (struct sockaddr*)&addr4;
	len = sizeof(addr4);

	if ((tcpsock[0] = socket(AF_INET, SOCK_STREAM, 0)) != -1) {
		if (setsockopt(tcpsock[0], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))
			== -1)
			log_warn("setting SO_REUSEADDR on socket");
		if (bind(tcpsock[0], addr, len) == -1) {
			close(tcpsock[0]);
			tcpsock[0] = -1;
		}
		if (listen(tcpsock[0], 5) == -1) {
			close(tcpsock[0]);
			tcpsock[0] = -1;
		}
	}

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(port);
	addr6.sin6_addr = in6addr_any;
	addr = (struct sockaddr*)&addr6;
	len = sizeof(addr6);

	if ((tcpsock[1] = socket(AF_INET6, SOCK_STREAM, 0)) != -1) {
		if (setsockopt(tcpsock[1], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))
			== -1)
			log_warn("setting SO_REUSEADDR on socket");
		if (bind(tcpsock[1], addr, len) == -1) {
			close(tcpsock[1]);
			tcpsock[1] = -1;
		}
		if (listen(tcpsock[1], 5) == -1) {
			close(tcpsock[1]);
			tcpsock[1] = -1;
		}
	}

	if (tcpsock[0] == -1 && tcpsock[1] == -1) {
		fatalx("Cannot bind to 0.0.0.0 or :: on Port 1965");
	}
}

int
open_pid_file(void)
{
	char buf[PID_BUF_SIZE];
	char pid_path[MAXREQLEN];
	int fd;

	snprintf(pid_path, MAXREQLEN, "%s/%s",
		_PATH_TWIND_CHROOT, _PATH_TWIND_PID);
	if ((fd = open(pid_path, O_CREAT|O_RDWR, 0600)) == -1)
		fatalx("Cannot open PID file");

	if (flock(fd, LOCK_EX|LOCK_NB) == -1)
		fatalx("Cannot get lock on PID file. Another instance running?");

	/*
	 * We need to truncate the file since the new PID could be shorter than
	 * an old one in the file.
	 */
	if (ftruncate(fd, 0) == -1)
		fatalx("Cannot truncate PID file");

	snprintf(buf, PID_BUF_SIZE, "%ld\n", (long) getpid());
	if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf))
		fatalx("Cannot write PID file");

	return fd;
}

static void
drop_root(void)
{
	struct passwd *pw;

	if (!(pw = getpwnam(TWIND_USER)))
		fatalx("Cannot find user entry for %s", TWIND_USER);

	if (!pw->pw_uid)
		fatalx("Cannot get UID entry for %s", TWIND_USER);

#ifdef __OpenBSD__
	if (unveil(_PATH_TWIND_CERT, "r") == -1)
		fatalx("unveil");
	if (unveil(_PATH_TWIND_KEY, "r") == -1)
		fatalx("unveil");
	if (unveil(_PATH_TWIND_CHROOT, "r") == -1)
		fatalx("unveil");
	if (unveil(_PATH_TWIND_PID_CHROOT, "r") == -1)
		fatalx("unveil");
	if (unveil(_PATH_TWIND_LOGS, "cw") == -1)
		log_warn("unveil");
	if (unveil(NULL, NULL) == -1)
		fatalx("unveil");
#endif /* __OpenBSD__ */

	if (chroot(_PATH_TWIND_CHROOT) == -1)
		fatalx("chroot() to %s failed", _PATH_TWIND_CHROOT);
	if (chdir("/") == -1)
		fatalx("chdir() failed");

	if (setgroups(1, &pw->pw_gid) == -1)
		fatalx("Cannot set group access list");
	if (setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) == -1)
		fatalx("Cannot set GUID to %d", pw->pw_gid);
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) == -1)
		fatalx("Cannot set UID to %d", pw->pw_uid);

}

