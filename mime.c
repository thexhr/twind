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

#include <stddef.h>
#include <string.h>

#include "log.h"
#include "twind.h"

struct mimetype {
	const char *ext;
	const char *type;
};

static const struct mimetype mime_collection[] = {
	{ "gmi", "text/gemini" },
	{ "gemini", "text/gemini" },
	{ "jpeg", "image/jpeg" },
	{ "jpg", "image/jpeg" },
	{ "html", "text/html" },
	{ "m4a", "audio/x-m4a" },
	{ "md", "text/markdown" },
	{ "mov", "video/quicktime" },
	{ "mp3", "audio/mpeg" },
	{ "mp4", "video/mp4" },
	{ "mpeg", "video/mpeg" },
	{ "mpg", "video/mpeg" },
	{ "ogg", "audio/ogg" },
	{ "pdf", "application/pdf" },
	{ "png", "image/png" },
	{ "svg", "image/svg+xml" },
	{ "txt", "text/plain" },
	{ "wmv", "video/x-ms-wmv" }
};

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

char *
get_file_extension(const char *path)
{
	char *p, *ext;

	if (strlen(path) == 0)
		return NULL;

	if ((p = strrchr(path, '.')) == NULL)
		return NULL;

	p += 1;
	ext = xstrdup(p);

	return ext;
}

char *
get_mime_type(const char *ext)
{
	char *mime = NULL;
	size_t len;
	long unsigned int i;

	if ((len = strlen(ext)) == 0)
		return NULL;

	for (i=0; i < nitems(mime_collection); i++)
		if (strcasecmp(ext, mime_collection[i].ext) == 0)
			mime = xstrdup(mime_collection[i].type);

	return mime;
}
