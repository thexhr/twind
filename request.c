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

#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "log.h"
#include "twind.h"

char hex_to_int(char);
char* uridecode(const char *);

/*
 * The following two functions are from https://geekhideout.com/urlcode.shtml
 * and provided without license restrictions
 */
char hex_to_int(char ch) {
	return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

char *
uridecode(const char *request)
{
	char *temp = xmalloc(strlen(request) + 1);
	const char *p;
	char *pt;

	p = request;
	pt = temp;

	while (*p) {
		if (*p == '%') {
			if (p[1] && p[2]) {
				*pt++ = hex_to_int(p[1]) << 4 | hex_to_int(p[2]);
				p += 2;
			}
		} else if (*p == '+') {
			*pt++ = ' ';
		} else {
			*pt++ = *p;
		}
		p++;
	}
	*pt = '\0';

	return temp;
}

int
get_path_from_request(char *request, char *finalpath)
{
	char hostname[MAXREQLEN];
	char localpath[MAXREQLEN];
	char temp[MAXREQLEN];
	char *p, *decoded_request;
	int pos = 0, ret;

	memset(hostname, 0, sizeof(hostname));
	memset(localpath, 0, sizeof(localpath));
	memset(temp, 0, sizeof(temp));

	p = request;

	if ((p = strchr(request, '\r')) == NULL) {
		log_info("\\r missing from request, abort processing");
		return -1;
	}

	*p = '\0';	/* Strip \r\n */
	p = request;

	if (strncmp(p, "gemini://", 9) != 0) {
		log_info("Gemini scheme missing, abort processing");
		return -1;
	}
	memmove(request, p + 9, strlen(request) + 1 - 9);

	decoded_request = uridecode(request);

	/* save hostname */
	if ((p = strchr(decoded_request, '/')) != NULL)
		snprintf(hostname, strlen(decoded_request) - strlen(p)+1, "%s",
			decoded_request);
	else
		snprintf(hostname, strlen(decoded_request)+1, "%s", decoded_request);

	/* Strip possible port (e.g. :1965) from hostname */
	if ((p = strrchr(hostname, ':')) != NULL) {
		pos = strlen(hostname) - strlen(p);
		if (pos < 0 || pos > _POSIX_HOST_NAME_MAX)
			fatalx("pos while shorten hostname out of range");
		hostname[pos] = '\0';
	}

	/* Remove ../ for security reasons */
	while ((p = strstr(decoded_request, "/..")) != NULL) {
		memmove(decoded_request, p + 3, strlen(p) + 1 - 3);
	}

	if ((p = strchr(decoded_request, '/')) != NULL) {
		/* Save all after the first / in localpath */
		snprintf(localpath, strlen(decoded_request), "%s", p+1);
		if (strlen(localpath) == 0) {
			/*
			 * If the request is 'example.com/', localpart will be empty. In this case
			 * write the default to it.
			 */
			sprintf(localpath, "index.gmi");
		}
	} else {
		/* There is no slash in the request, so assume index.gmi */
		sprintf(localpath, "index.gmi");
	}

	/*
	 *We do not need to take the base dir aka /var/db/gemini into account
	 * since we already chroot() to _PATH_TWIND_CHROOT .
	 *
	 * Here, a string truncation could happen.  This can be implemented
	 * better! XXX FIXME
	 */
	snprintf(finalpath, MAXREQLEN, "%s/%s", hostname, localpath);

	/* Check if the wanted path exists and if it's a directory */
	ret = check_gemini_file(finalpath);
	if (ret < 0) {
		log_debug("%s not found", finalpath);
		free(decoded_request);
		return -2;
	} else if (ret == 1) {
		log_debug("%s is a directory", finalpath);
		/* Auto append index.gmi if destination is a directory */
		snprintf(temp, MAXREQLEN, "%s", finalpath);
		snprintf(finalpath, MAXREQLEN, "%s/index.gmi", temp);
	}

	log_debug("Got request for %s on server %s -> %s",
		localpath, hostname, finalpath);

	/* decoded_request is no longer used, so it can be freed */
	free(decoded_request);

	return 0;
}

