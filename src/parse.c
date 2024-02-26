// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#ifndef PARSE_TEST
#include "masqmail.h"
#endif

/*
**  This is really dangerous. I hope that I was careful enough,
**  but maybe there is some malformed address possible that causes
**  this to segfault or be caught in endless loops.

**  If you find something like that, PLEASE mail the string to me
**  (no matter how idiotic it is), so that I can debug that.
**  Those things really should not happen.
*/

static gchar specials[] = "()<>@,;:\\\".[]`";

const char *parse_error = NULL;

static const gchar*
skip_comment(const gchar *p)
{

#ifdef PARSE_TEST
	g_print("skip_comment: %s\n", p);
#endif

	p++;  // skip opening '('
	for (;;) {
		if (!*p) {
			parse_error = "unterminated comment";
			return NULL;
		}
		if (*p == ')') {
			return p + 1;
		}
		if (*p == '(') {
			p = skip_comment(p);
		} else {
			p++;
		}
	}
}

static const gchar*
skip_cfws(const gchar *p)
{
	// eat white spaces and comments
	for (;;) {
		if (*p == '(') {
			p = skip_comment(p);
			if (!p) {
				return NULL;
			}
		} else if (isspace(*p)) {
			p++;
		} else {
			break;
		}
	}
	// we now have a non-space char that is not the beginning of a comment
	return p;
}

static const gchar *
read_qstring(const gchar *p)
{
	p++;
	while (*p && (*p != '\"')) {
		p++;
	}
	p++;
	return p;
}

static const gchar *
read_atom(const gchar *p)
{
	while (*p && !strchr(specials, *p) && !iscntrl(*p) && !isspace(*p)) {
		p++;
	}
	return p;
}

static const gchar *
read_dot_atom(const gchar *p)
{
	while (TRUE) {
		p = read_atom(p);
		if (*p != '.') {
			break;
		}
		p++;
	}
	return p;
}

static const gchar *
read_word_with_dots(const gchar *p)
{
#ifdef PARSE_TEST
	g_print("read_word_with_dots: %s\n", p);
#endif
	if (*p == '"') {
		return read_qstring(p);
	} else {
		return read_dot_atom(p);
	}
}

static const gchar *
read_domain(const gchar *p)
{
#ifdef PARSE_TEST
	g_print("read_domain: %s\n", p);
#endif
	if (*p != '[') {
		while (isalnum(*p) || (*p == '-') || (*p == '.')) {
			p++;
		}
	} else {
		p++;
		while (isalpha(*p) || (*p == '.')) {
			p++;
		}
		if (*p != ']') {
			parse_error = "unterminated domain literal";
			return NULL;
		}
		p++;
	}
	return p;
}

gboolean
parse_address_rfc822(const gchar *string,
                     const gchar **local_begin, const gchar **local_end,
                     const gchar **domain_begin, const gchar **domain_end,
                     const gchar **address_end)
{
	gint angle_brackets = 0;

	const gchar *p = string;
	const gchar *b, *e;

	*local_begin = *local_end = NULL;
	*domain_begin = *domain_end = NULL;

	/* leading spaces and angle brackets */
	while (*p && (isspace(*p) || (*p == '<'))) {
		if (*p == '<') {
			angle_brackets++;
		}
		p++;
	}

	if (!*p) {
		parse_error = "missing address";
		return FALSE;
	}

	while (TRUE) {
		b = p;
		if (!(p = read_word_with_dots(p))) {
			return FALSE;
		}
		e = p;
#ifdef PARSE_TEST
		g_print("after read_word_with_dots: %s\n", p);
#endif
		if (!(p = skip_cfws(p))) {
			return FALSE;
		}

		if (*p == '@' || (*p == ',' && address_end)) {
			/* the last word was the local_part of an addr-spec */
			*local_begin = b;
			*local_end = e;
#ifdef PARSE_TEST
			g_print("found local part: %s\n", *local_begin);
#endif
			if (*p == '@') {
				p++;	/* skip @ */
				/* now the domain */
				*domain_begin = p;
				if (!(p = read_domain(p))) {
					return FALSE;
				}
				*domain_end = p;
			} else {
				/* unqualified? */
				/* something like `To: alice, bob' with -t */
				*domain_begin = *domain_end = NULL;
			}
			break;

		} else if (*p == '<') {
			/* addr-spec follows */
			while (isspace(*p) || (*p == '<')) {
				if (*p == '<') {
					angle_brackets++;
				}
				p++;
			}
			*local_begin = p;
			if (!(p = read_word_with_dots(p))) {
				return FALSE;
			}
			*local_end = p;
#ifdef PARSE_TEST
			g_print("found local part: %s\n", *local_begin);
#endif
			if (*p == '@') {
				p++;
				*domain_begin = p;
				if (!(p = read_domain(p))) {
					return FALSE;
				}
				*domain_end = p;
			} else {
				/* may be unqualified address */
				*domain_begin = *domain_end = NULL;
			}
			break;

		} else if (!*p || *p == '>') {
			*local_begin = b;
			*local_end = e;
#ifdef PARSE_TEST
			g_print("found local part: %s\n", *local_begin);
#endif
			*domain_begin = *domain_end = NULL;
			break;

		} else if (strchr(specials, *p) || iscntrl(*p) || isspace(*p)) {
			parse_error = "unexpected character";
#ifdef PARSE_TEST
			g_print("unexpected character: %c", *p);
#endif
			return FALSE;
		}
	}

	/* trailing spaces and angle brackets */
#ifdef PARSE_TEST
	g_print("down counting trailing '>'\n");
#endif
	while (*p && (isspace(*p) || (*p == '>'))) {
		if (*p == '>') {
			angle_brackets--;
		}
		p++;
	}

	if (angle_brackets > 0) {
		parse_error = "missing '>' at end of string";
		return FALSE;
	} else if (angle_brackets < 0) {
		parse_error = "excess '>' at end of string";
		return FALSE;
	}

	if (address_end) {
		*address_end = p;
	}

	/* we successfully parsed the address */
	return TRUE;
}

gboolean
parse_address_rfc821(const gchar *string,
                     const gchar **local_begin, const gchar **local_end,
                     const gchar **domain_begin, const gchar **domain_end,
                     const gchar **address_end)
{
	gint angle_brackets = 0;

	const gchar *p = string;

	*local_begin = *local_end = NULL;
	*domain_begin = *domain_end = NULL;

	/* leading spaces and angle brackets */
	while (*p && (isspace(*p) || (*p == '<'))) {
		if (*p == '<') {
			angle_brackets++;
		}
		p++;
	}

	if (!*p) {
		parse_error = "missing address";
		return FALSE;
	}

	while (TRUE) {
		*local_begin = p;
		if (!(p = read_word_with_dots(p))) {
			return FALSE;
		}
		*local_end = p;
#ifdef PARSE_TEST
		g_print("found local part: %s\n", *local_begin);
		g_print("local_end = %s\n", *local_end);
#endif
		if (!(*p) || isspace(*p) || (*p == '>')) {
			/* unqualified ? */
			break;
		} else if (*p == '@') {
			p++;
			*domain_begin = p;
			if (!(p = read_domain(p))) {
				return FALSE;
			}
			*domain_end = p;
			break;
		} else {
			parse_error = "unexpected character after local part";
			return FALSE;
		}
	}

	/* trailing spaces and angle brackets */
#ifdef PARSE_TEST
	g_print("down counting trailing '>'\n");
#endif
	while (*p && (isspace(*p) || (*p == '>'))) {
		if (*p == '>') {
			angle_brackets--;
		}
		p++;
	}

	if (angle_brackets > 0) {
		parse_error = "missing '>' at end of string";
		return FALSE;
	} else if (angle_brackets < 0) {
		parse_error = "excess '>' at end of string";
		return FALSE;
	}

	if (address_end) {
		*address_end = p;
	} else if (*p) {
		parse_error = "excess characters at end of string";
		return FALSE;
	}

	/* we successfully parsed the address */
	return TRUE;
}
