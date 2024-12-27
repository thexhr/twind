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

#ifndef _TWIND_H
#define _TWIND_H

#include <netinet/in.h>

#include <openssl/ssl.h>

#include <signal.h>

#define VERSION "2024.a"
#define MAXREQLEN 1025
#define _PATH_TWIND_ACCESS_LOG "logs/access.log"
#define _PATH_TWIND_ERROR_LOG "logs/error.log"

enum status_codes {
	STATUS_INPUT = 10,
	STATUS_SENSITIVE_INPUT = 11,
	STATUS_SUCCESS = 20,
	STATUS_REDIRECT_TEMP = 30,
	STATUS_REDIRECT_PERM = 31,
	STATUS_TEMP_UNAVAILABLE = 40,
	STATUS_SERVER_UNAVAILABLE = 41,
	STATUS_CGI_ERROR = 42,
	STATUS_PROXY_ERROR = 43,
	STATUS_SLOW_DOWN = 44,
	STATUS_PERM_FAILURE = 50,
	STATUS_NOT_FOUND = 51,
	STATUS_GONE = 52,
	STATUS_PROXY_REQUEST_REFUSED = 53,
	STATUS_BAD_REQUEST = 59,
	STATUS_CLIENT_CERT_REQUIRED = 60,
	STATUS_CERT_NOT_AUTHORIZED = 61,
	STATUS_CERT_NOT_VALID = 62,
};

struct client_connection {
	SSL *ssl_peer;
	char client_addr[INET6_ADDRSTRLEN];
};

static volatile sig_atomic_t reload_log_files = 0;

/* gemini.c */
int check_gemini_file(const char *);
int send_response(SSL*, int, const char *, const char *);
int send_non_success_response(SSL*, int);

/* request.c */
int get_path_from_request(char *, char *);

/* mime.c */
char* get_file_extension(const char*);
char* get_mime_type(const char *);

/* util.c */
void* xmalloc(size_t);
char* xstrdup(const char *);
size_t strlcpy(char *, const char *, size_t);

/* log.c */
void open_twind_logs(void);
void close_twind_logs(void);
void log_access(const struct client_connection *, const char *, ...);
void log_error(const struct client_connection *, const char *, ...);
void user_log(int, const char *, ...);

#endif
