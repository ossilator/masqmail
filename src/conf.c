// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <pwd.h>
#include <grp.h>

masqmail_conf conf;

void
init_conf()
{
	struct passwd *passwd;
	struct group *group;

	if (!(passwd = getpwnam(DEF_MAIL_USER))) {
		fprintf(stderr, "user " DEF_MAIL_USER " not found! (terminating)\n");
		exit(1);
	}
	if (!(group = getgrnam(DEF_MAIL_GROUP))) {
		fprintf(stderr, "group " DEF_MAIL_GROUP " not found! (terminating)\n");
		exit(1);
	}
	conf.orig_uid = getuid();
	conf.orig_gid = getgid();
	conf.mail_uid = passwd->pw_uid;
	conf.mail_gid = group->gr_gid;
}

static const gchar * const true_strings[] = {
	"yes", "on", "true", NULL
};

static const gchar * const false_strings[] = {
	"no", "off", "false", NULL
};

static gboolean
parse_boolean(const gchar *rval)
{
	const gchar * const *str;

	DEBUG(9) fprintf(stderr, "parse_boolean: %s\n", rval);
	for (str = true_strings; *str; str++) {
		if (strncasecmp(*str, rval, strlen(*str))==0) {
			return TRUE;
		}
	}
	for (str = false_strings; *str; str++) {
		if (strncasecmp(*str, rval, strlen(*str))==0) {
			return FALSE;
		}
	}
	fprintf(stderr, "cannot parse value '%s'\n", rval);
	exit(1);
}

/*
** make a list from the lines of a file
*/
static GList*
parse_list_file(const gchar *fname)
{
	GList *list = NULL;
	FILE *fptr;
	gchar buf[256];

	if (!(fptr = fopen(fname, "rt"))) {
		logerrno(LOG_ERR, "could not open %s for reading", fname);
		exit(1);
	}
	while (fgets(buf, sizeof buf, fptr)) {
		g_strstrip(buf);
		if (!*buf || *buf == '#') {
			continue;
		}
		DEBUG(9) fprintf(stderr, "parse_list_file: item = %s\n", buf);
		list = g_list_append(list, g_strdup(buf));
	}
	fclose(fptr);

	return list;
}

/*
** given a semicolon separated string, this function makes a GList out of it.
*/
static GList*
parse_list(gchar *line, gboolean read_file)
{
	GList *list = NULL;
	gchar *tok;

	DEBUG(9) fprintf(stderr, "parsing list %s, file?:%d\n", line, read_file);
	for (tok = strtok(line, ";"); tok; tok = strtok(NULL, ";")) {
		g_strstrip(tok);
		if (!*tok) {
			continue;
		}
		DEBUG(9) fprintf(stderr, "item = %s\n", tok);
		if (read_file && *tok == '/') {
			/* item is a filename, include its contents */
			list = g_list_concat(list, parse_list_file(tok));
		} else {
			/* just a normal item */
			list = g_list_append(list, g_strdup(tok));
		}
	}
	return list;
}

/*
**  Split the addrs at '@' into local_part and domain. Without an '@'
**  everything is local_part. Create and return a list of address structs.
**  This function is used for lists of addrs containing globbing chars
**  (* and ?).  We don't need valid RFC821 addresses here, just patterns
**  to match against.
*/
static GList*
parse_address_glob_list(gchar *line)
{
	GList *plain_list = parse_list(line, TRUE);
	GList *list = NULL;

	foreach (gchar *item, plain_list) {
		char *at;
		address *addr;

		at = strrchr(item, '@');
		if (at) {
			*at = '\0';
			addr = create_address_raw(item, at + 1);
		} else {
			/* No `@', thus any domain is okay. */
			addr = create_address_raw(item, "*");
		}
		list = g_list_append(list, addr);
		DEBUG(6) debugf("parse_address_glob_list: read pattern `%s' `%s'\n",
		                addr->local_part, addr->domain);
	}
	destroy_ptr_list(plain_list);
	return list;
}

static GList*
parse_resolve_list(gchar *line)
{
	GList *list;
	GList *res_list = NULL;

	list = parse_list(line, TRUE);
	if (!list) {
		return NULL;
	}
	foreach (const gchar *item, list) {
		if (strcmp(item, "byname")==0) {
			res_list = g_list_append(res_list, resolve_byname);
#ifdef ENABLE_RESOLVER
		} else if (strcmp(item, "dns_mx")==0) {
			res_list = g_list_append(res_list, resolve_dns_mx);
#endif
		} else {
			logwrite(LOG_ERR, "unknown resolver %s\n", item);
			exit(1);
		}
	}
	destroy_ptr_list(list);
	return res_list;
}

static interface*
parse_interface(const gchar *line, gint def_port)
{
	const gchar *cp;
	interface *iface = g_malloc(sizeof(interface));

	DEBUG(9) fprintf(stderr, "parse_interface: %s\n", line);
	if ((cp = strchr(line, ':'))) {
		iface->address = g_strchomp(g_strndup(line, cp - line));
		iface->port = atoi(++cp);
	} else {
		iface->address = g_strdup(line);
		iface->port = def_port;
	}
	DEBUG(9) fprintf(stderr, "found: address:port=%s:%d\n",
			iface->address, iface->port);
	return iface;
}

static GList *
finalize_address_list(GList *addrs, const gchar *what)
{
	GList *out = NULL;

	foreach (const gchar *item, addrs) {
		address *a = create_address(item, A_RFC821, conf.host_name);
		if (!a) {
			logwrite(LOG_ERR, "invalid address '%s' in %s: %s\n",
			         item, what, parse_error);
			exit(1);
		}
		out = g_list_append(out, a);
	}
	destroy_ptr_list(addrs);
	return out;
}

static gboolean
eat_comments(FILE *in)
{
	gint c;
	int incomment = 0;

	while ((c = fgetc(in)) != EOF) {
		if (incomment) {
			/* eat until end of line */
			if (c == '\n') {
				incomment = 0;
				continue;
			} else {
				continue;
			}
		} else {
			/* eat whitespace and watch for comments */
			if (isspace(c)) {
				continue;
			} else if (c == '#') {
				incomment = 1;
				continue;
			} else {
				/* found something (that's not our business) */
				ungetc(c, in);
				return TRUE;
			}
		}
	}
	return FALSE;
}

static gboolean
eat_spaces(FILE *in)
{
	gint c;

	while ((c = fgetc(in)) != EOF) {
		if (!isspace(c)) {
			ungetc(c, in);
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
read_lval(FILE *in, gchar *buf, gint size)
{
	gint c;
	gchar *ptr = buf;

	DEBUG(9) fprintf(stderr, "read_lval()\n");
	if (!eat_spaces(in)) {
		return FALSE;
	}

	DEBUG(9) fprintf(stderr, "read_lval() 2\n");
	while (1) {
		c = fgetc(in);
		if (c == EOF) {
			fprintf(stderr, "unexpected EOF after %s\n", buf);
			return FALSE;
		}
		if (ptr >= buf+size-1) {
			fprintf(stderr, "lval too long\n");
			break;
		}
		if (!isalnum(c) && c != '_' && c != '-' && c != '.') {
			break;
		}
		*ptr++ = c;
	}
	*ptr = '\0';
	g_strchomp(buf);
	ungetc(c, in);
	eat_spaces(in);
	DEBUG(9) fprintf(stderr, "lval = %s\n", buf);
	return *buf != '\0';
}

static gboolean
read_rval(FILE *in, gchar *buf, gint size)
{
	gint c;
	gchar *ptr = buf;

	DEBUG(9) fprintf(stderr, "read_rval()\n");
	if (!eat_spaces(in)) {
		return FALSE;
	}

	c = fgetc(in);
	if (c != '"') {
		/* unquoted rval */
		ungetc(c, in);
		while ((c = fgetc(in)) != EOF) {
			if (ptr >= buf+size-1) {
				/* rval too long */
				break;
			}
			if (!isalnum(c) && c != '_' && c != '-' &&
					c != '.' && c != '/' && c != '@' &&
					c != ';' && c != ':') {
				break;
			}
			*ptr++ = c;
		}
		*ptr = '\0';
		ungetc(c, in);
	} else {
		/* quoted rval */
		gboolean escape = FALSE;
		while ((c = fgetc(in)) != EOF) {
			if (ptr >= buf+size-1) {
				/* rval too long */
				break;
			}
			if (!escape && c == '"') {
				break;
			}
			if (!escape && c == '\\') {
				escape = TRUE;
				continue;
			}
			*ptr++ = c;
			escape = FALSE;
		}
		*ptr = '\0';
	}
	g_strchomp(buf);
	DEBUG(9) fprintf(stderr, "rval = %s\n", buf);
	/* eat trailing of line */
	while ((c = fgetc(in)) != EOF && c != '\n') {
		continue;
	}

	return TRUE;
}

static gboolean
read_statement(FILE *in, gchar *lval, gint lsize, gchar *rval, gint rsize)
{
	gint c;

	DEBUG(9) fprintf(stderr, "read_statement()\n");

	/* eat comments and empty lines: */
	if (!eat_comments(in)) {
		return FALSE;
	}
	if (!read_lval(in, lval, lsize)) {
		return FALSE;
	}
	DEBUG(9) fprintf(stderr, "  lval = `%s'\n", lval);
	if ((c = fgetc(in) != '=')) {
		fprintf(stderr, "'=' expected after %s, char was '%c'\n", lval, c);
	}
	if (!read_rval(in, rval, rsize)) {
		return FALSE;
	}
	DEBUG(9) fprintf(stderr, "  rval = `%s'\n", rval);
	return TRUE;
}

gboolean
read_conf(void)
{
	FILE *in;
	gchar lval[256], rval[2048];
	gchar *log_user_tmp = NULL;
	GList *listen_addrs_tmp = NULL;
	GList *local_addrs_tmp = NULL;
	GList *not_local_addrs_tmp = NULL;
	GList *warn_intervals_tmp = NULL;

	conf.do_relay = TRUE;
	conf.localpartcmp = strcmp;
	conf.max_defer_time = 86400 * 4;  /* 4 days */
	conf.max_msg_size = 0; /* no limit on msg size */
	conf.pid_dir = PID_DIR;
	conf.log_dir = LOG_DIR;
	conf.lock_dir = LOCK_DIR;
	conf.spool_dir = SPOOL_DIR;
	conf.mail_dir = "/var/mail";

	if (!(in = fopen(conf.conf_file, "r"))) {
		logerrno(LOG_ERR, "could not open config file %s", conf.conf_file);
		return FALSE;
	}

	while (read_statement(in, lval, sizeof lval, rval, sizeof rval)) {
		DEBUG(9) fprintf(stderr,"read_conf(): lval=%s\n", lval);
		if (strcmp(lval, "debug_level")==0) {
			conf.debug_level = atoi(rval);
		} else if (strcmp(lval, "run_as_user")==0) {
			conf.run_as_user = parse_boolean(rval);
		} else if (strcmp(lval, "use_syslog")==0) {
			conf.use_syslog = parse_boolean(rval);
		} else if (strcmp(lval, "mail_dir")==0) {
			conf.mail_dir = g_strdup(rval);
		} else if (strcmp(lval, "lock_dir")==0) {
			conf.lock_dir = g_strdup(rval);
		} else if (strcmp(lval, "spool_dir")==0) {
			conf.spool_dir = g_strdup(rval);
		} else if (strcmp(lval, "log_dir")==0) {
			conf.log_dir = g_strdup(rval);
		} else if (strcmp(lval, "pid_dir")==0) {
			conf.pid_dir = g_strdup(rval);
		} else if (strcmp(lval, "host_name")==0) {
			if (rval[0] != '/') {
				conf.host_name = g_strdup(rval);
			} else {
				char buf[256];
				FILE *fptr = fopen(rval, "rt");
				if (!fptr) {
					logerrno(LOG_ERR, "could not open %s", rval);
					return FALSE;
				}
				fgets(buf, sizeof buf, fptr);
				g_strstrip(buf);
				conf.host_name = g_strdup(buf);
				fclose(fptr);
			}
		} else if (strcmp(lval, "local_hosts")==0) {
			conf.local_hosts = parse_list(rval, TRUE);
		} else if (strcmp(lval, "local_addresses")==0) {
			local_addrs_tmp = parse_list(rval, TRUE);
		} else if (strcmp(lval, "not_local_addresses")==0) {
			not_local_addrs_tmp = parse_list(rval, TRUE);
		} else if (strcmp(lval, "do_save_envelope_to")==0) {
			conf.do_save_envelope_to = parse_boolean(rval);
		} else if (strcmp(lval, "defer_all")==0) {
			conf.defer_all = parse_boolean(rval);
		} else if (strcmp(lval, "do_relay")==0) {
			conf.do_relay = parse_boolean(rval);
		} else if (strcmp(lval, "alias_file")==0) {
			conf.alias_file = g_strdup(rval);
		} else if (strcmp(lval, "globalias_file")==0) {
			conf.globalias_file = g_strdup(rval);
		} else if (strcmp(lval, "caseless_matching")==0) {
			conf.localpartcmp = parse_boolean(rval) ? strcasecmp : strcmp;
		} else if (strcmp(lval, "mbox_default")==0) {
			conf.mbox_default = g_strdup(rval);
		} else if (strcmp(lval, "mbox_users")==0) {
			conf.mbox_users = parse_list(rval, TRUE);
		} else if (strcmp(lval, "mda_users")==0) {
			conf.mda_users = parse_list(rval, TRUE);
		} else if (strcmp(lval, "mda")==0) {
			conf.mda = g_strdup(rval);
		} else if (strcmp(lval, "mda_fromline")==0) {
			conf.mda_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "mda_fromhack")==0) {
			conf.mda_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromline")==0) {
			conf.pipe_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromhack")==0) {
			conf.pipe_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "listen_addresses")==0) {
			listen_addrs_tmp = parse_list(rval, TRUE);
		} else if (strncmp(lval, "query_routes.", 13)==0) {
			GList *file_list = parse_list(rval, FALSE);
			table_pair *pair = create_pair_base(lval + 13, file_list);
			conf.query_routes = g_list_append(conf.query_routes, pair);
		} else if (strcmp(lval, "permanent_routes")==0) {
			conf.perma_routes = parse_list(rval, FALSE);
		} else if (strcmp(lval, "online_query")==0) {
			conf.online_query = g_strdup(rval);
		} else if (strcmp(lval, "do_queue")==0) {
			conf.do_queue = parse_boolean(rval);
		} else if (strcmp(lval, "errmsg_file")==0) {
			conf.errmsg_file = g_strdup(rval);
		} else if (strcmp(lval, "warnmsg_file")==0) {
			conf.warnmsg_file = g_strdup(rval);
		} else if (strcmp(lval, "warn_intervals")==0) {
			warn_intervals_tmp = parse_list(rval, TRUE);
		} else if (strcmp(lval, "max_defer_time")==0) {
			gint ival = time_interval(rval);
			if (ival < 0) {
				logwrite(LOG_ERR, "invalid time interval for 'max_defer_time': %s\n", rval);
				return FALSE;
			}
			conf.max_defer_time = ival;
		} else if (strcmp(lval, "log_user")==0) {
			log_user_tmp = g_strdup(rval);
		} else if(strcmp(lval, "max_msg_size")==0) {
			conf.max_msg_size = atol(rval);
			DEBUG(9) fprintf(stderr,
			                 "rval=%s, conf.max_msg_size=%" G_GSSIZE_FORMAT "\n",
			                 rval, conf.max_msg_size);
		} else {
			logwrite(LOG_WARNING, "var '%s' unknown: ignored\n", lval);
		}
	}
	fclose(in);

	if (!conf.host_name) {
		logwrite(LOG_ERR, "`host_name' MUST be set in masqmail.conf. See man page\n");
		return FALSE;
	}
	if (!conf.errmsg_file) {
		conf.errmsg_file = g_strdup(DATA_DIR "/tpl/failmsg.tpl");
	}
	if (!conf.warnmsg_file) {
		conf.warnmsg_file = g_strdup(DATA_DIR "/tpl/warnmsg.tpl");
	}
	if (!conf.mbox_default) {
		conf.mbox_default = g_strdup("mbox");
	}
	if (!warn_intervals_tmp) {
		static char def_ivals[] = "1h;4h;8h;1d;2d;3d";  // not const!
		warn_intervals_tmp = parse_list(def_ivals, TRUE);
	}
	foreach (const gchar *str_ival, warn_intervals_tmp) {
		gint ival = time_interval(str_ival);
		if (ival < 0) {
			logwrite(LOG_ERR, "invalid time interval for 'warn_intervals': %s\n", str_ival);
			return FALSE;
		}
		conf.warn_intervals = g_list_prepend(conf.warn_intervals, (gpointer) (gintptr) ival);
	}
	destroy_ptr_list(warn_intervals_tmp);
	if (!conf.local_hosts) {
		conf.local_hosts = g_list_append(NULL, g_strdup("localhost"));
		char *p = strchr(conf.host_name, '.');
		if (p) {
			conf.local_hosts = g_list_append(conf.local_hosts,
					g_strndup(conf.host_name, p - conf.host_name));
		}
		conf.local_hosts = g_list_append(conf.local_hosts,
		                                 g_strdup(conf.host_name));
	}
	if (log_user_tmp) {
		conf.log_user = create_recipient(log_user_tmp, conf.host_name);
		if (!conf.log_user) {
			logwrite(LOG_ERR, "invalid log_user address '%s': %s\n", log_user_tmp, parse_error);
			return FALSE;
		}
		free(log_user_tmp);
	}
	conf.local_addresses = finalize_address_list(
			local_addrs_tmp, "local_addresses");
	conf.not_local_addresses = finalize_address_list(
			not_local_addrs_tmp, "not_local_addresses");
	if (!listen_addrs_tmp) {
		conf.listen_addresses = g_list_append(NULL,
				parse_interface("localhost", 25));
	} else {
		foreach (const gchar *line, listen_addrs_tmp) {
			conf.listen_addresses = g_list_append(conf.listen_addresses,
					parse_interface(line, 25));
		}
		destroy_ptr_list(listen_addrs_tmp);
	}

	return TRUE;
}

static gboolean
parse_rewrite_map(gchar *rval, GList **out, addr_type_t addr_type)
{
	GList *list;
	gboolean ret = TRUE;

	list = parse_list(rval, TRUE);
	foreach (const gchar *item, list) {
		table_pair *pair = parse_table_pair(item, ':');
		gchar *repl = pair->value;
		replacement *addr;
		if (g_str_has_prefix(repl, "*@")) {
			addr = g_malloc0(sizeof(replacement));
			addr->address->domain = g_strdup(repl + 2);
			goto enlist;
		}
		addr = create_replacement(repl, addr_type);
		if (!addr) {
			logwrite(LOG_ALERT, "invalid replacement address '%s': %s\n", repl,
			         parse_error);
			destroy_pair(pair);
			ret = FALSE;
		} else if (!addr->address->domain[0]) {
			logwrite(LOG_ALERT, "replacement address '%s' lacks domain\n", repl);
			destroy_pair(pair);
			ret = FALSE;
		} else {
		  enlist:
			g_free(pair->value);
			pair->value = addr;
			*out = g_list_append(*out, pair);
		}
	}
	destroy_ptr_list(list);
	return ret;
}

static connect_route*
read_route(const gchar *filename)
{
	FILE *in;
	gboolean ok = TRUE;
	connect_route *route;
	gchar lval[256], rval[2048];

	DEBUG(5) debugf("read_route, filename = %s\n", filename);

	if (!(in = fopen(filename, "r"))) {
		logerrno(LOG_ERR, "could not open route file %s", filename);
		return NULL;
	}

	route = g_malloc0(sizeof(connect_route));
	route->filename = g_strdup(filename);
	route->name = route->filename;  /* quick hack */
	route->do_pipelining = TRUE;
	route->smtp_port = 25;

	while (read_statement(in, lval, sizeof lval, rval, sizeof rval)) {
		if (strcmp(lval, "mail_host")==0) {
			route->mail_host = parse_interface(rval, 25);
		} else if (strcmp(lval, "helo_name")==0) {
			route->helo_name = g_strdup(rval);
		} else if (strcmp(lval, "wrapper")==0) {
			route->wrapper = g_strdup(rval);
		} else if (strcmp(lval, "smtp_port")==0) {
			route->smtp_port = atol(rval);
		} else if (strcmp(lval, "connect_error_fail")==0) {
			route->connect_error_fail = parse_boolean(rval);
		} else if (strcmp(lval, "do_correct_helo")==0) {
			route->do_correct_helo = parse_boolean(rval);
		} else if (strcmp(lval, "instant_helo")==0) {
			route->instant_helo = parse_boolean(rval);
		} else if (strcmp(lval, "do_pipelining")==0) {
			route->do_pipelining = parse_boolean(rval);

		} else if (strcmp(lval, "allowed_senders")==0) {
			route->allowed_senders = parse_address_glob_list(rval);
		} else if (strcmp(lval, "denied_senders")==0) {
			route->denied_senders = parse_address_glob_list(rval);
		} else if (strcmp(lval, "allowed_recipients")==0) {
			route->allowed_recipients = parse_address_glob_list(rval);
		} else if (strcmp(lval, "denied_recipients")==0) {
			route->denied_recipients = parse_address_glob_list(rval);
		} else if (strcmp(lval, "allowed_from_hdrs")==0) {
			route->allowed_from_hdrs = parse_address_glob_list(rval);
		} else if (strcmp(lval, "denied_from_hdrs")==0) {
			route->denied_from_hdrs = parse_address_glob_list(rval);

		} else if (strcmp(lval, "map_return_path_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_return_path_addresses, A_RFC821);
		} else if (strcmp(lval, "map_h_from_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_h_from_addresses, A_RFC822);
		} else if (strcmp(lval, "map_h_sender_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_h_sender_addresses, A_RFC822);
		} else if (strcmp(lval, "map_h_reply_to_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_h_reply_to_addresses, A_RFC822);
		} else if (strcmp(lval, "map_h_mail_followup_to_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_h_mail_followup_to_addresses, A_RFC822);
		} else if (strcmp(lval, "map_outgoing_addresses")==0) {
			ok &= parse_rewrite_map(
					rval, &route->map_outgoing_addresses, A_RFC822);
		} else if (strcmp(lval, "resolve_list")==0) {
			route->resolve_list = parse_resolve_list(rval);
#ifdef ENABLE_AUTH
		} else if (strcmp(lval, "auth_name")==0) {
			route->auth_name = g_strdup(rval);
		} else if (strcmp(lval, "auth_login")==0) {
			route->auth_login = g_strdup(rval);
		} else if (strcmp(lval, "auth_secret")==0) {
			route->auth_secret = g_strdup(rval);
#else
		} else if ((strcmp(lval, "auth_name")==0) ||
				(strcmp(lval, "auth_login")==0) ||
				(strcmp(lval, "auth_secret")==0)) {
			logwrite(LOG_WARNING, "%s ignored: not compiled with auth support.\n", lval);
#endif
		} else if (strcmp(lval, "pipe")==0) {
			route->pipe = g_strdup(rval);
		} else if (strcmp(lval, "pipe_fromline")==0) {
			route->pipe_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromhack")==0) {
			route->pipe_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "last_route")==0) {
			route->last_route = parse_boolean(rval);
		} else {
			logwrite(LOG_WARNING, "var '%s' unknown: ignored\n", lval);
		}
	}

	if (!route->resolve_list) {
#ifdef ENABLE_RESOLVER
		route->resolve_list = g_list_append(route->resolve_list, resolve_dns_mx);
#endif
		route->resolve_list = g_list_append(route->resolve_list, resolve_byname);
	}
	fclose(in);

	if (!ok) {
		destroy_route(route);
		return NULL;
	}

	return route;
}

static void
destroy_address_list(GList *list)
{
	g_list_free_full(list, (GDestroyNotify) destroy_address);
}

void
destroy_replacement_pair(table_pair *p)
{
	destroy_replacement(p->value);
	destroy_pair_base(p);
}

static void
destroy_replacement_table(GList *list)
{
	g_list_free_full(list, (GDestroyNotify) destroy_replacement_pair);
}

void
destroy_route(connect_route *r)
{
	g_free(r->filename);
	if (r->mail_host) {
		g_free(r->mail_host->address);
		g_free(r->mail_host);
	}
	g_free(r->wrapper);
	g_free(r->helo_name);
	destroy_address_list(r->allowed_senders);
	destroy_address_list(r->denied_senders);
	destroy_address_list(r->allowed_recipients);
	destroy_address_list(r->denied_recipients);
	destroy_address_list(r->allowed_from_hdrs);
	destroy_address_list(r->denied_from_hdrs);
	destroy_replacement_table(r->map_h_from_addresses);
	destroy_replacement_table(r->map_h_sender_addresses);
	destroy_replacement_table(r->map_h_reply_to_addresses);
	destroy_replacement_table(r->map_h_mail_followup_to_addresses);
	destroy_replacement_table(r->map_return_path_addresses);
	destroy_replacement_table(r->map_outgoing_addresses);
	g_list_free(r->resolve_list);
#ifdef ENABLE_AUTH
	g_free(r->auth_name);
	g_free(r->auth_login);
	g_free(r->auth_secret);
#endif
	g_free(r->pipe);
	g_free(r);
}

GList*
read_route_list(const GList *rf_list)
{
	GList *list = NULL;

	acquire_root();
	foreach (const gchar *fname, rf_list) {
		connect_route *route = read_route(fname);
		if (route) {
			list = g_list_append(list, route);
		}
	}
	drop_root();
	return list;
}

void
destroy_route_list(GList *list)
{
	g_list_free_full(list, (GDestroyNotify) destroy_route);
}
