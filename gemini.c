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

#include <sys/socket.h>
#include <sys/stat.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "twind.h"

static void
generate_meta(int status_code, char *meta_response_string, const char *mime)
{
	switch(status_code) {
		case STATUS_INPUT:
			snprintf(meta_response_string, 1024, "%d Present input\r\n", status_code);
			break;
		case STATUS_SENSITIVE_INPUT:
			snprintf(meta_response_string, 1024, "%d Present sensitive input\r\n",
				status_code);
			break;
		case STATUS_SUCCESS:
			if (mime == NULL)
				/* Could not deducte mime type, so send text/gemini as default */
				snprintf(meta_response_string, 1024, "%d text/gemini\r\n", status_code);
			else
				snprintf(meta_response_string, 1024, "%d %s\r\n", status_code, mime);
			break;
		case STATUS_REDIRECT_TEMP:
			snprintf(meta_response_string, 1024, "%d Temporary redirect\r\n",
				status_code);
			break;
		case STATUS_REDIRECT_PERM:
			snprintf(meta_response_string, 1024, "%d Permanent redirect\r\n",
				status_code);
			break;
		case STATUS_TEMP_UNAVAILABLE:
			snprintf(meta_response_string, 1024, "%d Temporary failure\r\n",
				status_code);
			break;
		case STATUS_SERVER_UNAVAILABLE:
			snprintf(meta_response_string, 1024, "%d Server unavailable\r\n",
				status_code);
			break;
		case STATUS_CGI_ERROR:
			snprintf(meta_response_string, 1024, "%d CGI Error\r\n", status_code);
			break;
		case STATUS_PROXY_ERROR:
			snprintf(meta_response_string, 1024, "%d Proxy error\r\n", status_code);
			break;
		case STATUS_SLOW_DOWN:
			snprintf(meta_response_string, 1024, "%d Slow down\r\n", status_code);
			break;
		case STATUS_PERM_FAILURE:
			snprintf(meta_response_string, 1024, "%d Permanent failure\r\n", status_code);
			break;
		case STATUS_NOT_FOUND:
			snprintf(meta_response_string, 1024, "%d Resource not found\r\n",
				status_code);
			break;
		case STATUS_GONE:
			snprintf(meta_response_string, 1024, "%d Resource is gone\r\n", status_code);
			break;
		case STATUS_PROXY_REQUEST_REFUSED:
			snprintf(meta_response_string, 1024, "%d Proxy request refused\r\n",
				status_code);
			break;
		case STATUS_BAD_REQUEST:
			snprintf(meta_response_string, 1024, "%d Bad Request\r\n", status_code);
			break;
		case STATUS_CLIENT_CERT_REQUIRED:
			snprintf(meta_response_string, 1024, "%d Client Certificate Required\r\n",
				status_code);
			break;
		case STATUS_CERT_NOT_AUTHORIZED:
			snprintf(meta_response_string, 1024, "%d Certificate not authorized\r\n",
				status_code);
			break;
		case STATUS_CERT_NOT_VALID:
			snprintf(meta_response_string, 1024, "%d Certificate not valid\r\n",
				status_code);
			break;
		default:
			snprintf(meta_response_string, 1024, "%d Unkown status code\r\n",
				status_code);
			break;
	}
}

int
send_non_success_response(SSL *ssl_peer, int status_code)
{
	char meta[1024];

	memset(meta, 0, sizeof(meta));

	generate_meta(status_code, meta, NULL);

	log_debug("Send non success response to client: %d", status_code);

	if (SSL_write(ssl_peer, meta, strlen(meta)) <= 0) {
		log_warn("Could not send response to client");
		return -1;
	}

	return 0;
}

int
send_response(SSL *ssl_peer, int status_code, const char *gemini_file_path,
	const char *mime)
{
	char meta[1024];
	char buffer[1024];
	int fd = -1, len;

	// <STATUS><SPACE><META><CR><LF>

	memset(meta, 0, sizeof(meta));
	memset(buffer, 0, sizeof(buffer));

	generate_meta(status_code, meta, mime);

	if (SSL_write(ssl_peer, meta, strlen(meta)) <= 0) {
		log_warn("Could not send response to client");
		return -1;
	}

	/* Close connection and do not send a response if status code is not
	 * a SUCCESS code
	 */
	if (status_code < 30 && status_code >= 20) {
		fd = open(gemini_file_path, O_RDONLY);
		if (fd == -1) {
			log_warn("Cannot open requested file");
			goto out;
		}

		while ((len = read(fd, buffer, sizeof(buffer)-1)) > 0) {
			if (SSL_write(ssl_peer, buffer, len) <= 0) {
				log_warn("Could not send response to client");
				return -1;
			}
		}
	}

out:
	close(fd);

	return 0;
}

int
check_gemini_file(const char *gemini_file_path)
{
	struct stat sb;

	if (stat(gemini_file_path, &sb) == -1) {
		log_warn("Cannot open requested file");
		return -1;
	}

	if ((sb.st_mode & (S_IRUSR | S_IRGRP | S_IROTH)) == 0) {
		log_warn("Cannot read requested file");
		return -1;
	}

	if ((sb.st_mode & S_IFMT) == S_IFDIR)
		return 1;

	return 0;
}
