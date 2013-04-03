/*
**  MasqMail
**  Copyright (C) 1999-2001 Oliver Kurth
**  Copyright (C) 2010 markus schnalke <meillo@marmaro.de>
**
**  This program is free software; you can redistribute it and/or modify
**  it under the terms of the GNU General Public License as published by
**  the Free Software Foundation; either version 2 of the License, or
**  (at your option) any later version.
**
**  This program is distributed in the hope that it will be useful,
**  but WITHOUT ANY WARRANTY; without even the implied warranty of
**  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
**  GNU General Public License for more details.
**
**  You should have received a copy of the GNU General Public License
**  along with this program; if not, write to the Free Software
**  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include <pwd.h>
#include <grp.h>

#include "masqmail.h"

masqmail_conf conf;

void
init_conf()
{
	struct passwd *passwd;
	struct group *group;

	if (!(passwd = getpwnam(DEF_MAIL_USER))) {
		fprintf(stderr, "user %s not found! (terminating)\n",
				DEF_MAIL_USER);
		exit(1);
	}
	if (!(group = getgrnam(DEF_MAIL_GROUP))) {
		fprintf(stderr, "group %s not found! (terminating)\n",
				DEF_MAIL_GROUP);
		exit(1);
	}
	memset(&conf, 0, sizeof(masqmail_conf));
	conf.orig_uid = getuid();
	conf.orig_gid = getgid();
	conf.mail_uid = passwd->pw_uid;
	conf.mail_gid = group->gr_gid;
}

static gchar *true_strings[] = {
	"yes", "on", "true", NULL
};

static gchar *false_strings[] = {
	"no", "off", "false", NULL
};

static gboolean
parse_boolean(gchar *rval)
{
	gchar **str;

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
		logwrite(LOG_ALERT, "could not open %s for reading: %s\n",
				fname, strerror(errno));
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

	DEBUG(9) fprintf(stderr, "parsing list %s, file?:%d\n",
			line, read_file);
	for (tok = strtok(strdup(line), ";"); tok; tok = strtok(NULL, ";")) {
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
**  This funktion is used for lists of addrs containing globbing chars
**  (* and ?).  We don't need valid RFC821 addresses here, just patterns
**  to match against.
*/
static GList*
parse_address_glob_list(gchar *line)
{
	GList *plain_list = parse_list(line, TRUE);
	GList *node;
	GList *list = NULL;

	foreach(plain_list, node) {
		gchar *item = (gchar *) (node->data);
		char *at;
		char *ep;
		address *addr = calloc(1, sizeof(address));

		ep = item + strlen(item) - 1;
		if (*item == '<' && *ep == '>') {
			*item = '\0';
			*ep = '\0';
			g_strstrip(item);
		}

		addr->address = strdup(item);
		at = strrchr(item, '@');
		if (at) {
			*at = '\0';
			addr->local_part = strdup(item);
			addr->domain = strdup(at+1);
		} else {
			addr->local_part = strdup(item);
			/* No `@', thus any domain is okay. */
			addr->domain = "*";
		}
		list = g_list_append(list, addr);
		DEBUG(6) debugf("parse_address_glob_list: "
				"read pattern `%s' `%s'\n",
		                addr->local_part, addr->domain);
		g_free(item);
	}
	g_list_free(plain_list);
	return list;
}

static GList*
parse_resolve_list(gchar *line)
{
	GList *list;
	GList *list_node;
	GList *res_list = NULL;
	gchar *item;

	list = parse_list(line, TRUE);
	if (!list) {
		return NULL;
	}
	foreach(list, list_node) {
		item = (gchar *) list_node->data;
		if (strcmp(item, "byname")==0) {
			res_list = g_list_append(res_list, resolve_byname);
#ifdef ENABLE_RESOLVER
		} else if (strcmp(item, "dns_a")==0) {
			res_list = g_list_append(res_list, resolve_dns_a);
		} else if (strcmp(item, "dns_mx")==0) {
			res_list = g_list_append(res_list, resolve_dns_mx);
#endif
		} else {
			logwrite(LOG_ALERT, "unknown resolver %s\n", item);
			exit(1);
		}
		g_free(item);
	}
	g_list_free(list);
	return res_list;
}

static interface*
parse_interface(gchar *line, gint def_port)
{
	gchar *cp;
	interface *iface = g_malloc(sizeof(interface));

	DEBUG(9) fprintf(stderr, "parse_interface: %s\n", line);
	if ((cp = strchr(line, ':'))) {
		*cp = '\0';
	}
	g_strstrip(line);
	iface->address = g_strdup(line);
	iface->port = (cp) ? atoi(++cp) : def_port;
	DEBUG(9) fprintf(stderr, "found: address:port=%s:%u\n",
			iface->address, iface->port);
	return iface;
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
	g_strstrip(buf);
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
	g_strstrip(buf);
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
	g_strstrip(lval);
	DEBUG(9) fprintf(stderr, "  lval = `%s'\n", lval);
	if ((c = fgetc(in) != '=')) {
		fprintf(stderr, "'=' expected after %s, char was '%c'\n",
				lval, c);
	}
	if (!read_rval(in, rval, rsize)) {
		return FALSE;
	}
	g_strstrip(rval);
	DEBUG(9) fprintf(stderr, "  rval = `%s'\n", rval);
	return TRUE;
}

gboolean
read_conf(gchar *filename)
{
	FILE *in;
	gchar lval[256], rval[2048];
	GList *listen_addrs_tmp = NULL;

	conf.do_relay = TRUE;
	conf.localpartcmp = strcmp;
	conf.max_defer_time = 86400 * 4;  /* 4 days */
	conf.max_msg_size = 0; /* no limit on msg size */
	conf.lock_dir = LOCK_DIR;
	conf.spool_dir = SPOOL_DIR;
	conf.mail_dir = "/var/mail";

	if (!(in = fopen(filename, "r"))) {
		logwrite(LOG_ALERT, "could not open config file %s: %s\n",
				filename, strerror(errno));
		return FALSE;
	}

	while (read_statement(in, lval, sizeof lval, rval, sizeof rval)) {
		DEBUG(9) fprintf(stderr,"read_conf(): lval=%s\n", lval);
		if (strcmp(lval, "debug_level")==0) {
			conf.debug_level = atoi(rval);
		} else if (strcmp(lval, "run_as_user")==0) {
			if (!conf.run_as_user) {
				/* you should not be able to reset that flag */
				conf.run_as_user = parse_boolean(rval);
			}
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
		} else if (strcmp(lval, "host_name")==0) {
			if (rval[0] != '/') {
				conf.host_name = g_strdup(rval);
			} else {
				char buf[256];
				FILE *fptr = fopen(rval, "rt");
				if (!fptr) {
					logwrite(LOG_ALERT, "could not open "
							"%s: %s\n", rval,
							strerror(errno));
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
			conf.local_addresses = parse_list(rval, TRUE);
		} else if (strcmp(lval, "not_local_addresses")==0) {
			conf.not_local_addresses = parse_list(rval, TRUE);
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
			conf.localpartcmp = parse_boolean(rval) ?
					strcasecmp : strcmp;
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
			table_pair *pair = create_pair(lval+13, file_list);
			conf.query_routes = g_list_append(conf.query_routes,
					pair);
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
			conf.warn_intervals = parse_list(rval, TRUE);
		} else if (strcmp(lval, "max_defer_time")==0) {
			gint ival = time_interval(rval);
			if (ival < 0) {
				logwrite(LOG_WARNING, "invalid time interval "
						"for 'max_defer_time': %s\n",
						rval);
			} else {
				conf.max_defer_time = ival;
			}
		} else if (strcmp(lval, "log_user")==0) {
			conf.log_user = g_strdup(rval);
		} else if(strcmp(lval, "max_msg_size")==0) {
			conf.max_msg_size = atol(rval);
			DEBUG(9) fprintf(stderr,
					"rval=%s, conf.max_msg_size=%ld\n",
			                 rval, conf.max_msg_size);
		} else {
			logwrite(LOG_WARNING, "var '%s' unknown: ignored\n",
					lval);
		}
	}
	fclose(in);

	if (!conf.host_name) {
		logwrite(LOG_ALERT, "`host_name' MUST be set in "
				"masqmail.conf. See man page\n");
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
	if (!conf.warn_intervals) {
		conf.warn_intervals = parse_list("1h;4h;8h;1d;2d;3d", TRUE);
	}
	if (!conf.local_hosts) {
		char *shortname = strdup(conf.host_name);
		char *p = strchr(shortname, '.');
		if (p) {
			*p = '\0';
		}
		/* don't care if shortname and conf.host_name are the same */
		char *local_hosts_str = g_strdup_printf("localhost;%s;%s",
				shortname, conf.host_name);
		conf.local_hosts = parse_list(local_hosts_str, TRUE);
		free(shortname);
		free(local_hosts_str);
	}
	if (!listen_addrs_tmp) {
		conf.listen_addresses = g_list_append(NULL,
				parse_interface(strdup("localhost"), 25));
	} else {
		GList *node;

		foreach(listen_addrs_tmp, node) {
			conf.listen_addresses =
					g_list_append(conf.listen_addresses,
					parse_interface((gchar *) node->data,
					25));
			g_free(node->data);
		}
		g_list_free(listen_addrs_tmp);
	}

	return TRUE;
}

connect_route*
read_route(gchar *filename, gboolean is_perma)
{
	FILE *in;
	connect_route *route;
	gchar lval[256], rval[2048];

	DEBUG(5) debugf("read_route, filename = %s\n", filename);

	if (!(in = fopen(filename, "r"))) {
		logwrite(LOG_ALERT, "could not open route file %s: %s\n",
				filename, strerror(errno));
		return NULL;
	}

	route = g_malloc(sizeof(connect_route));
	memset(route, 0, sizeof(connect_route));
	route->filename = g_strdup(filename);
	route->name = route->filename;  /* quick hack */
	route->expand_h_sender_address = TRUE;
	route->is_perma = is_perma;
	route->do_pipelining = TRUE;

	while (read_statement(in, lval, sizeof lval, rval, sizeof rval)) {
		if (strcmp(lval, "mail_host")==0) {
			route->mail_host = parse_interface(rval, 25);
		} else if (strcmp(lval, "helo_name")==0) {
			route->helo_name = g_strdup(rval);
		} else if (strcmp(lval, "wrapper")==0) {
			route->wrapper = g_strdup(rval);
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

		} else if (strcmp(lval, "set_h_from_domain")==0) {
			route->set_h_from_domain = g_strdup(rval);
		} else if (strcmp(lval, "set_h_reply_to_domain")==0) {
			route->set_h_reply_to_domain = g_strdup(rval);
		} else if (strcmp(lval, "set_return_path_domain")==0) {
			route->set_return_path_domain = g_strdup(rval);
		} else if (strcmp(lval, "map_return_path_addresses")==0) {
			GList *node, *list;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				address *addr = create_address(
						(gchar *) (pair->value), TRUE);
				g_free(pair->value);
				pair->value = (gpointer *) addr;
				route->map_return_path_addresses = g_list_append(route->map_return_path_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_from_addresses")==0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_from_addresses = g_list_append(route->map_h_from_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_reply_to_addresses")==0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_reply_to_addresses = g_list_append(route->map_h_reply_to_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_mail_followup_to_addresses")==0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_mail_followup_to_addresses = g_list_append(route->map_h_mail_followup_to_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "expand_h_sender_domain")==0) {
			route->expand_h_sender_domain = parse_boolean(rval);
		} else if (strcmp(lval, "expand_h_sender_address")==0) {
			route->expand_h_sender_address = parse_boolean(rval);
		} else if (strcmp(lval, "resolve_list")==0) {
			route->resolve_list = parse_resolve_list(rval);
		} else if (strcmp(lval, "do_ssl")==0) {
			/* we ignore this. This option is used by sqilconf */
			;
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
			logwrite(LOG_WARNING, "%s ignored: not compiled with "
					"auth support.\n", lval);
		}
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
			logwrite(LOG_WARNING, "var '%s' unknown: ignored\n",
					lval);
		}
	}

	if (!route->resolve_list) {
#ifdef ENABLE_RESOLVER
		route->resolve_list = g_list_append(route->resolve_list,
				resolve_dns_mx);
		route->resolve_list = g_list_append(route->resolve_list,
				resolve_dns_a);
#endif
		route->resolve_list = g_list_append(route->resolve_list,
				resolve_byname);
	}
	fclose(in);

	/* warn user about mis-configurations: */
	if (route->map_h_from_addresses && route->set_h_from_domain) {
		logwrite(LOG_WARNING, "'map_h_from_addresses' overrides "
				"'set_h_from_domain'\n");
		g_free(route->set_h_from_domain);
		route->set_h_from_domain = NULL;
	}
	if (route->map_h_reply_to_addresses && route->set_h_reply_to_domain) {
		logwrite(LOG_WARNING, "'map_h_reply_to_addresses' overrides "
				"'set_h_reply_to_domain'\n");
		g_free(route->set_h_reply_to_domain);
		route->set_h_reply_to_domain = NULL;
	}

	return route;
}

static void
_g_list_free_all(GList *list)
{
	GList *node;
	if (!list) {
		return;
	}
	foreach(list, node) {
		g_free(node->data);
	}
	g_list_free(list);
}

void
destroy_route(connect_route *r)
{
	if (r->filename) {
		g_free(r->filename);
	}
	if (r->mail_host) {
		g_free(r->mail_host->address);
		g_free(r->mail_host);
	}
	if (r->wrapper) {
		g_free(r->wrapper);
	}
	if (r->helo_name) {
		g_free(r->helo_name);
	}
	_g_list_free_all(r->allowed_senders);
	_g_list_free_all(r->denied_senders);
	_g_list_free_all(r->allowed_recipients);
	_g_list_free_all(r->denied_recipients);
	if (r->set_h_from_domain) {
		g_free(r->set_h_from_domain);
	}
	if (r->set_h_reply_to_domain) {
		g_free(r->set_h_reply_to_domain);
	}
	if (r->set_return_path_domain) {
		g_free(r->set_return_path_domain);
	}
	if (r->map_h_reply_to_addresses) {
		destroy_table(r->map_h_reply_to_addresses);
	}
	if (r->resolve_list) {
		g_list_free(r->resolve_list);
	}
#ifdef ENABLE_AUTH
	if (r->auth_name) {
		g_free(r->auth_name);
	}
	if (r->auth_login) {
		g_free(r->auth_login);
	}
	if (r->auth_secret) {
		g_free(r->auth_secret);
	}
#endif
	if (r->pipe) {
		g_free(r->pipe);
	}
	g_free(r);
}

GList*
read_route_list(GList *rf_list, gboolean is_perma)
{
	GList *list = NULL;
	GList *node;
	uid_t saved_uid, saved_gid;

	if (!conf.run_as_user) {
		set_euidgid(0, 0, &saved_uid, &saved_gid);
	}
	foreach(rf_list, node) {
		gchar *fname = (gchar *) (node->data);
		connect_route *route = read_route(fname, is_perma);
		if (route) {
			list = g_list_append(list, route);
		} else {
			logwrite(LOG_ALERT, "could not read route "
					"configuration %s\n", fname);
		}
	}
	/* set uid and gid back */
	if (!conf.run_as_user) {
		set_euidgid(saved_uid, saved_gid, NULL, NULL);
	}
	return list;
}

void
destroy_route_list(GList *list)
{
	GList *node;

	foreach(list, node) {
		connect_route *route = (connect_route *) (node->data);
		destroy_route(route);
	}
	g_list_free(list);
}
