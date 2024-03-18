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

	p++;
	while (*p && *p != ')') {
		p++;
		if (*p == '(') {
			p = skip_comment(p);
		}
	}
	p++;

	return p;
}

static gboolean
read_word(const gchar *p, const gchar **b, const gchar **e)
{
#ifdef PARSE_TEST
	g_print("read_word: %s\n", p);
#endif
	/* eat leading spaces */
	while (*p && isspace(*p)) {
		p++;
	}

	*b = p;
	/*  b = &p; */
	if (*p == '\"') {
		/* quoted-string */
		p++;
		while (*p && (*p != '\"')) {
			p++;
		}
		p++;
	} else {
		/* atom */
		while (*p && !strchr(specials, *p) && !iscntrl(*p) && !isspace(*p)) {
			p++;
		}
	}
	*e = p;
	return TRUE;
}

static gboolean
read_word_with_dots(const gchar *p, const gchar **b, const gchar **e)
{
	const gchar *b0 = p;

#ifdef PARSE_TEST
	g_print("read_word_with_dots: %s\n", p);
#endif
	while (TRUE) {
		if (!read_word(p, b, e)) {
			return FALSE;
		}
		p = *e;
		if (*p != '.') {
			break;
		}
		p++;
	}
	*b = b0;
	*e = p;
	return TRUE;
}

static gboolean
read_domain(const gchar *p, const gchar **b, const gchar **e)
{
#ifdef PARSE_TEST
	g_print("read_domain: %s\n", p);
#endif
	*b = p;
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
			return FALSE;
		}
		p++;
	}
	*e = p;
	return TRUE;
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
		if (!read_word_with_dots(p, &b, &e)) {
			return FALSE;
		}

		p = e;
#ifdef PARSE_TEST
		g_print("after read_word_with_dots: %s\n", p);
#endif
		/* eat white spaces and comments */
		while ((*p && (isspace(*p))) || (*p == '(')) {
			if (*p == '(') {
				if (!(p = skip_comment(p))) {
					parse_error = "unterminated comment";
					return FALSE;
				}
			} else {
				p++;
			}
		}
		/*
		**  we now have a non-space char that is not
		**  the beginning of a comment
		*/

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
				if (!read_domain(p, &b, &e)) {
					return FALSE;
				}
				p = e;
				*domain_begin = b;
				*domain_end = e;
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
			if (!read_word_with_dots(p, &b, &e)) {
				return FALSE;
			}
			p = e;
			*local_begin = b;
			*local_end = e;
#ifdef PARSE_TEST
			g_print("found local part: %s\n", *local_begin);
#endif
			if (*p == '@') {
				p++;
				if (!read_domain(p, &b, &e)) {
					return FALSE;
				}
				p = e;
				*domain_begin = b;
				*domain_end = e;
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
		if (!read_word_with_dots(p, &b, &e)) {
			return FALSE;
		}

		p = e;
#ifdef PARSE_TEST
		g_print("after read_word_with_dots: %s\n", p);
#endif
		*local_begin = b;
		*local_end = e;
#ifdef PARSE_TEST
		g_print("found local part: %s\n", *local_begin);
		g_print("local_end = %s\n", *local_end);
#endif
		if (!(*p) || isspace(*p) || (*p == '>')) {
			/* unqualified ? */
			domain_begin = domain_end = NULL;
			break;
		} else if (*p == '@') {
			p++;
			if (read_domain(p, &b, &e)) {
				p = e;
				*domain_begin = b;
				*domain_end = e;
			}
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
