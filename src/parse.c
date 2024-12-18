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
			if (*p == '\\') {
				p++;
				if (!*p) {
					parse_error = "unterminated backslash escape inside comment";
					return NULL;
				}
			}
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
	while (TRUE) {
		p++;
		if (!*p) {
			parse_error = "unterminated quoted string";
			return NULL;
		}
		if (*p == '"') {
			return p + 1;
		}
		if (*p == '\\') {
			p++;
			if (!*p) {
				parse_error = "unterminated backslash escape inside quoted string";
				return NULL;
			}
		}
	}
}

static const gchar *
read_atom(const gchar *p)
{
	while (*p && !strchr(specials, *p) && !iscntrl(*p) && !isspace(*p)) {
		p++;
	}
	return p;
}

typedef enum { NO_DOTS, ANY_DOTS, BAD_DOTS } has_dots_t;

static const gchar *
read_dot_atom(const gchar *p, has_dots_t *had_dots_out)
{
	has_dots_t had_dots = NO_DOTS;
	while (TRUE) {
		const gchar *pp = p;
		p = read_atom(p);
		if (*p != '.') {
			if (p == pp && had_dots == ANY_DOTS) {
				had_dots = BAD_DOTS;
			}
			break;
		}
		if (p == pp) {
			had_dots = BAD_DOTS;
		} else if (had_dots != BAD_DOTS) {
			had_dots = ANY_DOTS;
		}
		p++;
	}
	if (had_dots > *had_dots_out) {
		*had_dots_out = had_dots;
	}
	return p;
}

static const gchar *
read_word_with_dots(const gchar *p, has_dots_t *had_dots)
{
#ifdef PARSE_TEST
	g_print("read_word_with_dots: %s\n", p);
#endif
	if (*p == '"') {
		return read_qstring(p);
	} else {
		return read_dot_atom(p, had_dots);
	}
}

static const gchar *
read_domain(const gchar *p)
{
	const gchar *op = p;
#ifdef PARSE_TEST
	g_print("read_domain: %s\n", p);
#endif
	if (*p != '[') {
		while (isalnum(*p) || (*p == '-') || (*p == '.')) {
			p++;
		}
	} else {
		for (;;) {
			p++;
			if (!*p) {
				parse_error = "unterminated domain literal";
				return NULL;
			}
			if (*p == '[') {
				parse_error = "'[' not allowed inside domain literal";
				return NULL;
			}
			if (*p == ']') {
				break;
			}
			if (*p == '\\') {
				p++;
				if (!*p) {
					parse_error = "unterminated backslash escape inside domain literal";
					return FALSE;
				}
			}
		}
		p++;
	}
	if (p == op) {
		parse_error = "empty domain";
		return FALSE;
	}
	return p;
}

gboolean
parse_address_rfc822(const gchar *string,
                     const gchar **local_begin, const gchar **local_end,
                     const gchar **domain_begin, const gchar **domain_end,
                     const gchar **address_end)
{
	has_dots_t had_dots = NO_DOTS;
	gint angle_brackets = 0;

	const gchar *p = string;
	const gchar *b = NULL, *e = NULL, *pb = NULL;

	*local_begin = *local_end = NULL;
	*domain_begin = *domain_end = NULL;

	while (TRUE) {
		if (!(p = skip_cfws(p))) {
			return FALSE;
		}

		if (*p == '>' || (*p == ',' && address_end) || !*p) {
			if (b) {
				if (pb || *local_begin) {
					// adjacent words are fine only in the display-name phrase,
					// but the context precludes that we are in that.
					// words after we had an address are of course bogus, too.
					parse_error = "excess word";
#ifdef PARSE_TEST
					g_print("excess word: %.*s", (int)(e - b), b);
#endif
					return FALSE;
				}
				if (had_dots == BAD_DOTS) {
					parse_error = "invalid periods in local part";
					return FALSE;
				}
				// unqualified, something like `To: alice, bob' with -t
				*local_begin = b;
				*local_end = e;
#ifdef PARSE_TEST
				g_print("found local part: %s\n", *local_begin);
#endif
			}
			if (!*p || *p == ',') {
				break;
			}
			angle_brackets--;
			b = e = pb = NULL;
			p++;
		} else if (*p == '<') {
			if (had_dots != NO_DOTS) {
				parse_error = "unquoted periods in display name";
				return FALSE;
			}
			angle_brackets++;
			b = e = pb = NULL;
			p++;
		} else if (*p == '@') {
			p++;

			if (!b) {
				// this might be a legacy source route, but we just reject these.
				parse_error = "missing local part";
				return FALSE;
			}
			if (pb) {
				parse_error = "excess word";
#ifdef PARSE_TEST
				g_print("excess word: %.*s", (int)(e - b), b);
#endif
				return FALSE;
			}
			/* the last word was the local_part of an addr-spec */
			if (*local_begin) {
				parse_error = "excess '@'";
				return FALSE;
			}
			if (had_dots == BAD_DOTS) {
				parse_error = "invalid periods in local part";
				return FALSE;
			}
			*local_begin = b;
			*local_end = e;
#ifdef PARSE_TEST
			g_print("found local part: %s\n", *local_begin);
#endif

			if (!(p = skip_cfws(p))) {
				return FALSE;
			}
			// now the domain
			*domain_begin = p;
			if (!(p = read_domain(p))) {
				return FALSE;
			}
			*domain_end = p;
			b = e = pb = NULL;
		} else {
			pb = b;
			b = p;
			if (!(p = read_word_with_dots(p, &had_dots))) {
				return FALSE;
			}
			e = p;
			if (e == b) {
				parse_error = "unexpected character";
#ifdef PARSE_TEST
				g_print("unexpected character: %c", *p);
#endif
				return FALSE;
			}
			p = e;
		}
	}

	if (angle_brackets > 0) {
		parse_error = "missing '>' at end of string";
		return FALSE;
	} else if (angle_brackets < 0) {
		parse_error = "excess '>' at end of string";
		return FALSE;
	} else if (!*local_begin) {
		parse_error = "missing address";
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
	has_dots_t had_dots = NO_DOTS;
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

	while (*p) {
		*local_begin = p;
		if (!(p = read_word_with_dots(p, &had_dots))) {
			return FALSE;
		}
		if (had_dots == BAD_DOTS) {
			parse_error = "invalid periods in local part";
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
	} else if (!*local_begin) {
		parse_error = "missing address";
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
