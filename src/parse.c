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

char *parse_error = NULL;

static gchar*
skip_comment(gchar *p)
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
read_word(gchar *p, gchar **b, gchar **e)
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
read_word_with_dots(gchar *p, gchar **b, gchar **e)
{
	gchar *b0 = p;

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
read_domain(gchar *p, gchar **b, gchar **e)
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
			parse_error = g_strdup_printf("']' expected at end of literal address %s", *b);
			return FALSE;
		}
		p++;
	}
	*e = p;
	return TRUE;
}

gboolean
parse_address_rfc822(gchar *string, gchar **local_begin, gchar **local_end,
		gchar **domain_begin, gchar **domain_end, gchar **address_end)
{
	gint angle_brackets = 0;

	gchar *p = string;
	gchar *b, *e;

	*local_begin = *local_end = NULL;
	*domain_begin = *domain_end = NULL;

	/* might be some memory left from previous call: */
	if (parse_error) {
		g_free(parse_error);
		parse_error = NULL;
	}

	/* leading spaces and angle brackets */
	while (*p && (isspace(*p) || (*p == '<'))) {
		if (*p == '<') {
			angle_brackets++;
		}
		p++;
	}

	if (!*p) {
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
					parse_error = g_strdup("missing right bracket ')'");
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

		if (*p == '@' || *p == ',') {
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
			parse_error = g_strdup_printf("unexpected character: %c", *p);
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

	*address_end = p;

	if (angle_brackets > 0) {
		parse_error = g_strdup("missing '>' at end of string");
		return FALSE;
	} else if (angle_brackets < 0) {
		parse_error = g_strdup("superfluous '>' at end of string");
		return FALSE;
	}

	/* we successfully parsed the address */
	return TRUE;
}

gboolean
parse_address_rfc821(gchar *string, gchar **local_begin, gchar **local_end,
		gchar **domain_begin, gchar **domain_end, gchar **address_end)
{
	gint angle_brackets = 0;

	gchar *p = string;
	gchar *b, *e;

	*local_begin = *local_end = NULL;
	*domain_begin = *domain_end = NULL;

	/* might be some memory left from previous call: */
	if (parse_error != NULL) {
		g_free(parse_error);
		parse_error = NULL;
	}

	/* leading spaces and angle brackets */
	while (*p && (isspace(*p) || (*p == '<'))) {
		if (*p == '<') {
			angle_brackets++;
		}
		p++;
	}

	if (!*p) {
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
			parse_error = g_strdup_printf ("unexpected character after local part '%c'", *p);
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
	*address_end = p;

	if (angle_brackets > 0) {
		parse_error = g_strdup("missing '>' at end of string");
		return FALSE;
	} else if (angle_brackets < 0) {
		parse_error = g_strdup("superfluous '>' at end of string");
		return FALSE;
	}

	/* we successfully parsed the address */
	return TRUE;
}

/*
**  allocate address, reading from string.
**  On failure, returns NULL.
**  after call, end contains a pointer to the end of the parsed string
**  end may be NULL, if we are not interested.
**
**  parses both rfc 821 and rfc 822 addresses, depending on flag is_rfc821
*/
address*
_create_address(gchar *string, gchar **end, gboolean is_rfc821)
{
	gchar *loc_beg, *loc_end;
	gchar *dom_beg, *dom_end;
	gchar *addr_end;
	gboolean ret;

	if (!string) {
		return NULL;
	}
	while (isspace(*string)) {
		string++;
	}
	/* TODO: what about (string == NULL)? */
	if (string && (string[0] == '\0')) {
		address *addr = g_malloc(sizeof(address));
		addr->address = g_strdup("");
		addr->local_part = g_strdup("");
		/*
		** 'NULL' address: failure notice
		** "": will *not* be qualified with a hostname
		*/
		addr->domain = g_strdup("");
		return addr;
	}

	if (is_rfc821) {
		ret = parse_address_rfc821(string, &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end);
	} else {
		ret = parse_address_rfc822(string, &loc_beg, &loc_end, &dom_beg, &dom_end, &addr_end);
	}
	if (!ret) {
		return NULL;
	}
	if (*loc_beg == '|') {
		parse_error = g_strdup("no pipe allowed for RFC 822/821 address");
		return NULL;
	}

	address *addr = g_malloc0(sizeof(address));

	gchar *p = addr_end;
	while (*p && (*p != ',')) {
		/* it seems as if we do this for the code in rewrite.c */
		p++;
	}
	addr->address = g_strstrip(g_strndup(string, p - string));
	addr->local_part = g_strndup(loc_beg, loc_end - loc_beg);

#ifdef PARSE_TEST
	g_print("addr->local_part = %s\n", addr->local_part);
#endif

	if (dom_beg != NULL) {
		addr->domain = g_strndup(dom_beg, dom_end - dom_beg);
	} else if (addr->local_part[0] == '\0') {
		/*
		** 'NULL' address: failure notice
		** "": will *not* be qualified with a hostname
		*/
		addr->domain = g_strdup("");
	} else {
		addr->domain = NULL;
	}

	if (end) {
		*end = p;
	}

	DEBUG(6) debugf("_create_address(): address: `%s'\n", addr->address);
	DEBUG(6) debugf("_create_address(): local_part: `%s'\n", addr->local_part);
	DEBUG(6) debugf("_create_address(): domain: `%s'\n", addr->domain);

#ifndef PARSE_TEST
	addr_unmark_delivered(addr);
#endif

	return addr;
}

GList*
addr_list_append_rfc822(GList *addr_list, gchar *string, gchar *domain)
{
	gchar *p = string;
	gchar *end;

	while (*p) {
#ifdef PARSE_TEST
		g_print("string: %s\n", p);
#endif

		address *addr = _create_address(p, &end, FALSE);
		if (!addr) {
			break;
		}

#ifdef PARSE_TEST
		g_print("addr: %s (%s<@>%s)", addr->address, addr->local_part, addr->domain);
#endif
		if (domain && !addr->domain) {
			addr->domain = g_strdup(domain);
		}
#ifdef PARSE_TEST
		g_print(" (%s<@>%s)\n", addr->local_part, addr->domain);
#endif

		addr_list = g_list_append(addr_list, addr);
		p = end;

		while (*p == ',' || isspace(*p)) {
			p++;
		}
	}
	return addr_list;
}
