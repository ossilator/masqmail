// SPDX-FileCopyrightText: (C) 2024 Oswald Buddenhagen <oswald.buddenhagen@gmx.de>
// SPDX-License-Identifier: GPL-2.0-or-later

#define TEST_BUILD
#include "parse.c"

typedef struct {
	char *addr, *local, *domain, *err;
	gboolean failok;
} rfc821_addr_test;

static const rfc821_addr_test rfc821_addrs[] = {
	{ "", NULL, NULL, "missing address", FALSE },
	{ " ", NULL, NULL, "missing address", FALSE },

	// basic addr-spec (these are actually malformed, but we're lenient,
	// mostly because we (ab-)use the parser for user config as well).
	{ "user", "user", NULL, NULL, FALSE },
	{ "  user ", "user", NULL, NULL, FALSE },
	{ "a.user", "a.user", NULL, NULL, FALSE },
	{ "user garbage", NULL, NULL, "excess characters at end of string", FALSE },
	{ "\"a user\"", "\"a user\"", NULL, NULL, FALSE },
	{ "user@example.com", "user", "example.com", NULL, FALSE },
	{ "\"one@two\"@example.com", "\"one@two\"", "example.com", NULL, FALSE },
	{ "user @ example.com", NULL, NULL, "excess characters at end of string", FALSE },

	// proper angle-addr
	{ "<>", "", NULL, NULL, FALSE },
	{ "<user>", "user", NULL, NULL, FALSE },
	{ "  <user> ", "user", NULL, NULL, FALSE },
	{ "<user", NULL, NULL, "missing '>' at end of string", FALSE },
	{ "<user>>", NULL, NULL, "excess '>' at end of string", FALSE },
	{ "user>", NULL, NULL, "excess '>' at end of string", FALSE },
	{ "<gärbage>", NULL, NULL, "unexpected 8-bit character", TRUE },
	{ " garbage <user>", NULL, NULL, "excess characters at end of string", FALSE },
	{ "<user@example.com>", "user", "example.com", NULL, FALSE },
	{ "<\"one@two\"@example.com>", "\"one@two\"", "example.com", NULL, FALSE },
	{ "<@dom1,@dom2:user@example.com>", "user", "example.com", NULL, TRUE },
			// source routes must be ignored
	{ "< user @ example.com >", NULL, NULL, "missing '>' at end of string", FALSE },
	{ "<user@example.com garbage>", NULL, NULL, "missing '>' at end of string", FALSE },
	{ "<user@example.com> garbage", NULL, NULL, "excess characters at end of string", FALSE },
	{ "<user[@example.com>", NULL, NULL, "unexpected character after local part", FALSE },
};

typedef struct {
	char *addr, *local, *domain;
	int end;
	char *err;
	gboolean failok;
} rfc822_addr_test;

static const rfc822_addr_test rfc822_addrs[] = {
	{ "", NULL, NULL, -1, "missing address", FALSE },
	{ " ", NULL, NULL, -1, "missing address", FALSE },

	// basic addr-spec
	{ "user", "user", NULL, -1, NULL, FALSE },
	{ "  user ", "user", NULL, -1, NULL, FALSE },
	{ "user, another", "user", NULL, 4, NULL, FALSE },
	{ "user , another", "user", NULL, 5, NULL, FALSE },
	{ "a.user", "a.user", NULL, -1, NULL, FALSE },
	{ "gärbage, another", NULL, NULL, -1, "unexpected 8-bit character", TRUE },
	{ "\"gärbage\", another", NULL, NULL, -1, "unexpected 8-bit character", TRUE },
	{ "g\\\x80rbage, another", NULL, NULL, -1, "unexpected 8-bit character", TRUE },
	{ "\"a user\"", "\"a user\"", NULL, -1, NULL, FALSE },
	// ... with domain
	{ "user@example.com", "user", "example.com", -1, NULL, FALSE },
	{ "a.user@example.com", "a.user", "example.com", -1, NULL, FALSE },
	{ "\"one@two\"@example.com", "\"one@two\"", "example.com", -1, NULL, FALSE },
	{ "user[@example.com, another", NULL, NULL, -1, "unexpected character", FALSE },
	// ... with comments
	{ "(left) user (right) (rightmost)", "user", NULL, -1, NULL, FALSE },
	{ "(left)user(right)", "user", NULL, -1, NULL, FALSE },
	{ "( (cmt) ) user", "user", NULL, -1, NULL, FALSE },
	{ "(cmt1, (cmt2)) user", "user", NULL, -1, NULL, FALSE },
	{ "user (cmt) ), another", NULL, NULL, -1, "unexpected character", FALSE },

	// angle-addr
	{ "<user>", "user", NULL, -1, NULL, FALSE },
	{ "  < user > ", "user", NULL, -1, NULL, FALSE },
	{ "<user>, another", "user", NULL, 6, NULL, FALSE },
	{ "<user> , another", "user", NULL, 7, NULL, FALSE },
	{ "<user, another", NULL, NULL, -1, "missing '>' at end of string", FALSE },
	{ "<user>>, another", NULL, NULL, -1, "excess '>' at end of string", FALSE },
	{ "user>, another", NULL, NULL, -1, "excess '>' at end of string", FALSE },
	// ... with domain
	{ "<user@example.com>", "user", "example.com", -1, NULL, FALSE },
	{ "<@dom1,@dom2:user@example.com>", "user", "example.com", -1, NULL, TRUE },
			// source routes must be ignored

	// display-name plus angle-addr
	{ "Real Name <user@example.com>", "user", "example.com", -1, NULL, FALSE },
	{ "\"Real Name\" <user@example.com>", "user", "example.com", -1, NULL, FALSE },
};

static int
test_str(const gchar *begin, const gchar *end, const char *ref)
{
	int refl = ref ? strlen(ref) : 0;
	return (end - begin) == refl && !memcmp(begin, ref, refl);
}

int
main(void)
{
	int ret = 0;
	const gchar *local_begin, *local_end;
	const gchar *domain_begin, *domain_end;
	const gchar *address_end;

	for (guint i = 0; i < G_N_ELEMENTS(rfc821_addrs); i++) {
		const rfc821_addr_test *ent = &rfc821_addrs[i];
		parse_error = NULL;
		gboolean ok = parse_address_rfc821(ent->addr, &local_begin, &local_end,
		                                   &domain_begin, &domain_end, NULL);
		if ((ok != !ent->err) ||
		    (ok && !(test_str(local_begin, local_end, ent->local) &&
		             test_str(domain_begin, domain_end, ent->domain))) ||
		    (!ok && ent->err && (!parse_error || strcmp(parse_error, ent->err)))) {
			printf("%sFAIL RFC821 '%s'\n  want: '%s' '%s' %s\n  got:  '%.*s' '%.*s' %s\n",
			       ent->failok ? "X" : "", ent->addr,
			       ent->local, ent->domain,
			       ent->err ? ent->err : "OK",
			       local_begin ? (int)(local_end - local_begin) : 6,
			       local_begin ? local_begin : "(null)",
			       domain_begin ? (int)(domain_end - domain_begin) : 6,
			       domain_begin ? domain_begin : "(null)",
			       ok ? "OK" : parse_error ? parse_error : "(no error code)");
			if (!ent->failok)
				ret = 1;
		} else {
			printf("%sPASS RFC821 '%s'\n", ent->failok ? "X" : "", ent->addr);
			if (ent->failok)
				ret = 1;
		}
	}
	for (guint i = 0; i < G_N_ELEMENTS(rfc822_addrs); i++) {
		const rfc822_addr_test *ent = &rfc822_addrs[i];
		address_end = NULL;
		parse_error = NULL;
		gboolean ok = parse_address_rfc822(ent->addr, &local_begin, &local_end,
		                                   &domain_begin, &domain_end, &address_end);
		if ((ok != !ent->err) ||
		    (ok && !(test_str(local_begin, local_end, ent->local) &&
		             test_str(domain_begin, domain_end, ent->domain) &&
		             ((ent->end == -1) ? (address_end && !*address_end) :
		                                 (address_end - ent->addr == ent->end)))) ||
		    (!ok && ent->err && (!parse_error || strcmp(parse_error, ent->err)))) {
			printf("%sFAIL RFC822 '%s'\n  want: '%s' '%s' '%s' %s\n  got:  '%.*s' '%.*s' '%s' %s\n",
			       ent->failok ? "X" : "", ent->addr,
			       ent->local, ent->domain,
			       (ent->end < 0) ? "(null)" : ent->addr + ent->end,
			       ent->err ? ent->err : "OK",
			       local_begin ? (int)(local_end - local_begin) : 6,
			       local_begin ? local_begin : "(null)",
			       domain_begin ? (int)(domain_end - domain_begin) : 6,
			       domain_begin ? domain_begin : "(null)",
			       (ok && address_end) ? address_end : "(null)",
			       ok ? "OK" : parse_error ? parse_error : "(no error code)");
			if (!ent->failok)
				ret = 1;
		} else {
			printf("%sPASS RFC822 '%s'\n", ent->failok ? "X" : "", ent->addr);
			if (ent->failok)
				ret = 1;
		}
	}
	return ret;
}
