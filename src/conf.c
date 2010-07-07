/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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

	memset(&conf, 0, sizeof(masqmail_conf));

	conf.orig_uid = getuid();
	conf.orig_gid = getgid();

	if ((passwd = getpwnam(DEF_MAIL_USER)))
		conf.mail_uid = passwd->pw_uid;
	else {
		fprintf(stderr, "user %s not found! (terminating)\n", DEF_MAIL_USER);
		exit(EXIT_FAILURE);
	}
	if ((group = getgrnam(DEF_MAIL_GROUP)))
		conf.mail_gid = group->gr_gid;
	else {
		fprintf(stderr, "group %s not found! (terminating)\n", DEF_MAIL_GROUP);
		exit(EXIT_FAILURE);
	}
}

static gchar* true_strings[] = {
	"yes", "on", "true", NULL
};

static gchar *false_strings[] = {
	"no", "off", "false", NULL
};

static gboolean
parse_boolean(gchar * rval)
{
	gchar **str;

	DEBUG(6) fprintf(stderr, "parse_boolean: %s\n", rval);

	str = true_strings;
	while (*str) {
		if (strncasecmp(*str, rval, strlen(*str)) == 0)
			return TRUE;
		str++;
	}

	str = false_strings;
	while (*str) {
		if (strncasecmp(*str, rval, strlen(*str)) == 0)
			return FALSE;
		str++;
	}

	fprintf(stderr, "cannot parse value '%s'\n", rval);
	exit(EXIT_FAILURE);
}

/* make a list from each line in a file */
static GList*
parse_list_file(gchar * fname)
{
	GList *list = NULL;
	FILE *fptr;

	if ((fptr = fopen(fname, "rt")) == NULL) {
		logwrite(LOG_ALERT, "could not open %s for reading: %s\n", fname, strerror(errno));
		exit(EXIT_FAILURE);
	}

	gchar buf[256];

	while (!feof(fptr)) {
		fgets(buf, 255, fptr);
		if (buf[0] && (buf[0] != '#') && (buf[0] != '\n')) {
			g_strchomp(buf);
			DEBUG(6) fprintf(stderr,"parse_list_file: item = %s\n", buf);
			list = g_list_append(list, g_strdup(buf));
		}
	}
	fclose(fptr);

	return list;
}

/* given a semicolon separated string, this function makes a GList out of it. */
GList*
parse_list(gchar * line, gboolean read_file)
{
	GList *list = NULL;
	gchar buf[256];
	gchar *p, *q;

	DEBUG(6) fprintf(stderr, "parsing list %s, file?:%d\n", line, read_file);

	p = line;
	while (*p != '\0') {
		q = buf;

		while (*p && (*p != ';') && (q < buf + 255))
			*(q++) = *(p++);
		*q = '\0';

		if ((buf[0] == '/') && (read_file))
			/* item is a filename, include its contents */
			list = g_list_concat(list, parse_list_file(buf));
		else
			/* just a normal item */
			list = g_list_append(list, g_strdup(buf));

		DEBUG(6) fprintf(stderr, "item = %s\n", buf);

		if (*p)
			p++;
	}
	return list;
}

static GList*
parse_address_list(gchar * line, gboolean read_file)
{
	GList *plain_list = parse_list(line, read_file);
	GList *node;
	GList *list = NULL;

	foreach(plain_list, node) {
		gchar *item = (gchar *) (node->data);
		address *addr = create_address(item, TRUE);
		if (addr)
			list = g_list_append(list, addr);
		g_free(item);
	}
	g_list_free(plain_list);

	return list;
}

static GList*
parse_resolve_list(gchar * line)
{
	GList *list;
	GList *list_node;
	GList *res_list = NULL;

	list = parse_list(line, FALSE);
	if (!list) {
		return NULL;
	}

	foreach(list, list_node) {
		gchar *item = (gchar *) (list_node->data);
		if (strcmp(item, "byname") == 0) {
			res_list = g_list_append(res_list, resolve_byname);
#ifdef ENABLE_RESOLVER
		} else if (strcmp(item, "dns_a") == 0) {
			res_list = g_list_append(res_list, resolve_dns_a);
		} else if (strcmp(item, "dns_mx") == 0) {
			res_list = g_list_append(res_list, resolve_dns_mx);
#endif
		} else {
			logwrite(LOG_ALERT, "unknown resolver %s\n", item);
			exit(EXIT_FAILURE);
		}
		g_free(item);
	}
	g_list_free(list);
	return res_list;
}

static interface*
parse_interface(gchar * line, gint def_port)
{
	gchar buf[256];
	gchar *p, *q;
	interface *iface;

	DEBUG(6) fprintf(stderr, "parse_interface: %s\n", line);

	p = line;
	q = buf;
	while ((*p != '\0') && (*p != ':') && (q < buf + 255))
		*(q++) = *(p++);
	*q = '\0';

	iface = g_malloc(sizeof(interface));
	iface->address = g_strdup(buf);

	if (*p) {
		p++;
		iface->port = atoi(p);
	} else
		iface->port = def_port;
	DEBUG(6) fprintf(stderr,"rval=%s, address:port=%s:%i\n",line, iface->address, iface->port);

	return iface;
}

#ifdef ENABLE_IDENT  /* so far used for that only */
static struct in_addr*
parse_network(gchar * line, gint def_port)
{
	gchar buf[256];
	gchar *p, *q;
	struct in_addr addr, mask_addr, net_addr, *p_net_addr;
	guint n;

	DEBUG(6) fprintf(stderr, "parse_network: %s\n", line);

	p = line;
	q = buf;
	while ((*p != '\0') && (*p != '/') && (q < buf + 255))
		*(q++) = *(p++);
	*q = '\0';

	if ((addr.s_addr = inet_addr(buf)) == INADDR_NONE) {
		fprintf(stderr, "'%s' is not a valid address (must be ip)\n", buf);
		exit(EXIT_FAILURE);
	}

	if (*p) {
		guint i;
		p++;
		i = atoi(p);
		if ((i >= 0) && (i <= 32))
			n = i ? ~((1 << (32 - i)) - 1) : 0;
		else {
			fprintf(stderr, "'%d' is not a valid net mask (must be >= 0 and <= 32)\n", i);
			exit(EXIT_FAILURE);
		}
	} else
		n = 0;

	mask_addr.s_addr = htonl(n);
	net_addr.s_addr = mask_addr.s_addr & addr.s_addr;

	p_net_addr = g_malloc(sizeof(struct in_addr));
	p_net_addr->s_addr = net_addr.s_addr;
	return p_net_addr;
}
#endif

static gboolean
eat_comments(FILE * in)
{
	gint c;

	for (c = fgetc(in); (c == '#' || isspace(c)) && c != EOF;
		 c = fgetc(in)) {
		if (c == '#') {
			gint c;
			for (c = fgetc(in); (c != '\n') && (c != EOF); c = fgetc(in));
		}
	}
	if (c == EOF)
		return FALSE;
	ungetc(c, in);
	return TRUE;
}

/* after parsing, eat trailing character until LF */
static gboolean
eat_line_trailing(FILE * in)
{
	gint c;

	for (c = fgetc(in); c != EOF && c != '\n'; c = fgetc(in));
	if (c == EOF)
		return FALSE;
	return TRUE;
}

static gboolean
eat_spaces(FILE * in)
{
	gint c;

	for (c = fgetc(in); c != EOF && isspace(c); c = fgetc(in)) {
		/* empty */
	}
	if (c == EOF)
		return FALSE;
	ungetc(c, in);
	return TRUE;
}

static gboolean
read_lval(FILE * in, gchar * buf, gint size)
{
	gint c;
	gchar *ptr = buf;

	DEBUG(6) fprintf(stderr, "read_lval()\n");

	if (!eat_spaces(in))
		return FALSE;

	c = fgetc(in);
	DEBUG(6) fprintf(stderr, "read_lval() 2\n");
	while ((isalnum(c) || c == '_' || c == '-' || c == '.')
	       && (ptr < buf + size - 1)
	       && (c != EOF)) {
		*ptr = c;
		ptr++;
		c = fgetc(in);
	}
	*ptr = '\0';
	ungetc(c, in);

	if (c == EOF) {
		fprintf(stderr, "unexpected EOF after %s\n", buf);
		return FALSE;
	} else if (ptr >= buf + size - 1) {
		fprintf(stderr, "lval too long\n");
	}

	eat_spaces(in);

	DEBUG(6) fprintf(stderr, "lval = %s\n", buf);

	return buf[0] != '\0';
}

static gboolean
read_rval(FILE * in, gchar * buf, gint size)
{
	gint c;
	gchar *ptr = buf;

	DEBUG(6) fprintf(stderr, "read_rval()\n");

	if (!eat_spaces(in))
		return FALSE;

	c = fgetc(in);
	if (c != '\"') {
		while ((isalnum(c) || c == '_' || c == '-' || c == '.'
		        || c == '/' || c == '@' || c == ';' || c == ':')
		       && (ptr < buf + size - 1)
		       && (c != EOF)) {
			*ptr = c;
			ptr++;
			c = fgetc(in);
		}
		*ptr = '\0';
		ungetc(c, in);
	} else {
		gboolean escape = FALSE;
		c = fgetc(in);
		while (((c != '\"') || escape) && (ptr < buf + size - 1)) {
			if (c != '\n') {  /* ignore line breaks */
				if ((c == '\\') && (!escape)) {
					escape = TRUE;
				} else {
					*ptr = c;
					ptr++;
					escape = FALSE;
				}
			}
			c = fgetc(in);
		}
		*ptr = '\0';
	}

	eat_line_trailing(in);

	DEBUG(6) fprintf(stderr, "rval = %s\n", buf);

	return TRUE;
}

static gboolean
read_statement(FILE * in, gchar * lval, gint lsize, gchar * rval, gint rsize)
{
	gint c;

	DEBUG(6) fprintf(stderr, "read_statement()\n");

	/* eat comments and empty lines: */
	if (!eat_comments(in))
		return FALSE;

	if (!read_lval(in, lval, lsize)) {
		return FALSE;
	}

	DEBUG(6) fprintf(stderr, "  lval = %s\n", lval);
	if ((c = fgetc(in) == '=')) {
		if (read_rval(in, rval, rsize)) {
			DEBUG(6) fprintf(stderr, "  rval = %s\n", rval);
			return TRUE;
		}
	} else {
		DEBUG(6) fprintf(stderr,"  '=' expected after %s, char was '%c'\n", lval, c);
		fprintf(stderr, "'=' expected after %s, char was '%c'\n", lval, c);
	}
	return FALSE;
}

gboolean
read_conf(gchar * filename)
{
	FILE *in;

	conf.log_max_pri = 7;
	conf.remote_port = 25;
	conf.do_relay = TRUE;
	conf.alias_local_cmp = strcmp;
	conf.max_defer_time = 86400 * 4;  /* 4 days */
	conf.max_msg_size = 0; /* no limit on msg size */
	conf.spool_dir = SPOOL_DIR;
	conf.log_dir = LOG_DIR;

	if ((in = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "could not open config file %s: %s\n", filename, strerror(errno));
		return FALSE;
	}

	gchar lval[256], rval[2048];
	while (read_statement(in, lval, 256, rval, 2048)) {
		DEBUG(6) fprintf(stderr,"read_conf(): lval=%s\n", lval);
		if (strcmp(lval, "debug_level") == 0)
			conf.debug_level = atoi(rval);
		else if (strcmp(lval, "run_as_user") == 0) {
			if (!conf.run_as_user)  /* you should not be able to reset that flag */
				conf.run_as_user = parse_boolean(rval);
		} else if (strcmp(lval, "use_syslog") == 0)
			conf.use_syslog = parse_boolean(rval);
		else if (strcmp(lval, "mail_dir") == 0)
			conf.mail_dir = g_strdup(rval);
		else if (strcmp(lval, "lock_dir") == 0)
			conf.lock_dir = g_strdup(rval);
		else if (strcmp(lval, "spool_dir") == 0)
			conf.spool_dir = g_strdup(rval);
		else if (strcmp(lval, "log_dir") == 0)
			conf.log_dir = g_strdup(rval);
		else if (strcmp(lval, "host_name") == 0) {
			if (rval[0] != '/')
				conf.host_name = g_strdup(rval);
			else {
				char buf[256];
				FILE *fptr = fopen(rval, "rt");
				if (fptr) {
					fprintf(stderr, "could not open %s: %s\n", rval, strerror(errno));
					return FALSE;
				}
				fgets(buf, 255, fptr);
				g_strchomp(buf);
				conf.host_name = g_strdup(buf);
				fclose(fptr);
			}
		} else if (strcmp(lval, "remote_port") == 0) {
			fprintf(stderr, "the remote_port option is now deprecated. Use 'mail_host' in the\n"
							"route configuration instead. See man masqmail.route\n");
			conf.remote_port = atoi(rval);
		} else if (strcmp(lval, "local_hosts") == 0)
			conf.local_hosts = parse_list(rval, FALSE);
		else if (strcmp(lval, "local_addresses") == 0)
			conf.local_addresses = parse_list(rval, TRUE);
		else if (strcmp(lval, "not_local_addresses") == 0)
			conf.not_local_addresses = parse_list(rval, TRUE);
		else if (strcmp(lval, "local_nets") == 0)
			conf.local_nets = parse_list(rval, FALSE);
		else if (strcmp(lval, "do_save_envelope_to") == 0)
			conf.do_save_envelope_to = parse_boolean(rval);
		else if (strcmp(lval, "defer_all") == 0)
			conf.defer_all = parse_boolean(rval);
		else if (strcmp(lval, "do_relay") == 0)
			conf.do_relay = parse_boolean(rval);
		else if (strcmp(lval, "alias_file") == 0) {
			conf.alias_file = g_strdup(rval);
		} else if (strcmp(lval, "alias_local_caseless") == 0) {
			conf.alias_local_cmp = parse_boolean(rval) ? strcasecmp : strcmp;
		} else if (strcmp(lval, "mbox_default") == 0) {
			conf.mbox_default = g_strdup(rval);
		} else if (strcmp(lval, "mbox_users") == 0) {
			conf.mbox_users = parse_list(rval, TRUE);
		} else if (strcmp(lval, "mda_users") == 0) {
			conf.mda_users = parse_list(rval, TRUE);
		} else if (strcmp(lval, "maildir_users") == 0) {
			conf.maildir_users = parse_list(rval, TRUE);
		} else if (strcmp(lval, "mda") == 0) {
			conf.mda = g_strdup(rval);
		} else if (strcmp(lval, "mda_fromline") == 0) {
			conf.mda_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "mda_fromhack") == 0) {
			conf.mda_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromline") == 0) {
			conf.pipe_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromhack") == 0) {
			conf.pipe_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "listen_addresses") == 0) {
			GList *node;
			GList *tmp_list = parse_list(rval, FALSE);

			conf.listen_addresses = NULL;
			foreach(tmp_list, node) {
				conf.listen_addresses = g_list_append(conf.listen_addresses, parse_interface((gchar *) (node-> data), 25));
				g_free(node->data);
			}
			g_list_free(tmp_list);
		} else if (strcmp(lval, "ident_trusted_nets") == 0) {
#ifdef ENABLE_IDENT
			GList *node;
			GList *tmp_list = parse_list(rval, FALSE);

			conf.ident_trusted_nets = NULL;
			foreach(tmp_list, node) {
				conf.ident_trusted_nets = g_list_append(conf.ident_trusted_nets, parse_network((gchar *) (node->data), 25));
				g_free(node->data);
			}
			g_list_free(tmp_list);
#else
			fprintf(stderr, "%s ignored: not compiled with ident support\n", lval);
#endif
		} else if ((strncmp(lval, "connect_route.", 14) == 0)
		           || (strncmp(lval, "online_routes.", 14) == 0)) {
			GList *file_list = parse_list(rval, FALSE);
			table_pair *pair = create_pair(&(lval[14]), file_list);
			conf.connect_routes = g_list_append(conf.connect_routes, pair);
		} else if (strcmp(lval, "local_net_route") == 0) {
			conf.local_net_routes = parse_list(rval, FALSE);
		} else if (strcmp(lval, "online_detect") == 0)
			conf.online_detect = g_strdup(rval);
		else if (strcmp(lval, "online_file") == 0)
			conf.online_file = g_strdup(rval);
		else if (strcmp(lval, "online_pipe") == 0)
			conf.online_pipe = g_strdup(rval);
		else if (strcmp(lval, "mserver_iface") == 0)
			conf.mserver_iface = parse_interface(rval, 224);
		else if (strcmp(lval, "do_queue") == 0)
			conf.do_queue = parse_boolean(rval);
		else if (strncmp(lval, "get.", 4) == 0) {
#ifdef ENABLE_POP3
			table_pair *pair = create_pair_string(&(lval[4]), rval);
			conf.get_names = g_list_append(conf.get_names, pair);
#else
			fprintf(stderr, "get.<name> ignored: not compiled with pop support\n");
#endif
		} else if (strncmp(lval, "online_gets.", 12) == 0) {
#ifdef ENABLE_POP3
			GList *file_list = parse_list(rval, FALSE);
			table_pair *pair = create_pair(&(lval[12]), file_list);
			conf.online_gets = g_list_append(conf.online_gets, pair);
#else
			fprintf(stderr, "online_gets.<name> ignored: not compiled with pop support\n");
#endif
		} else if (strcmp(lval, "errmsg_file") == 0)
			conf.errmsg_file = g_strdup(rval);
		else if (strcmp(lval, "warnmsg_file") == 0)
			conf.warnmsg_file = g_strdup(rval);
		else if (strcmp(lval, "warn_intervals") == 0)
			conf.warn_intervals = parse_list(rval, FALSE);
		else if (strcmp(lval, "max_defer_time") == 0) {
			gint dummy;
			gint ival = time_interval(rval, &dummy);
			if (ival < 0)
				fprintf(stderr, "invalid time interval for 'max_defer_time': %s\n", rval);
			else
				conf.max_defer_time = ival;
		} else if (strcmp(lval, "log_user") == 0)
			conf.log_user = g_strdup(rval);
		else if(strcmp(lval, "max_msg_size") == 0) {
			conf.max_msg_size = atol(rval);
			DEBUG(6) fprintf(stderr,"rval=%s, conf.max_msg_size=%ld\n",
			                 rval, conf.max_msg_size);
		}
		else
			fprintf(stderr, "var '%s' not (yet) known, ignored\n", lval);
	}
	fclose(in);

	if (conf.errmsg_file == NULL)
		conf.errmsg_file = g_strdup(DATA_DIR "/tpl/failmsg.tpl");
	if (conf.warnmsg_file == NULL)
		conf.warnmsg_file = g_strdup(DATA_DIR "/tpl/warnmsg.tpl");

	if (conf.lock_dir == NULL)
		conf.lock_dir = g_strdup_printf("%s/lock/", conf.spool_dir);

	if (conf.mbox_default == NULL)
		conf.mbox_default = g_strdup("mbox");

	if (conf.warn_intervals == NULL)
		conf.warn_intervals = parse_list("1h;4h;8h;1d;2d;3d", FALSE);

	return TRUE;
}

connect_route*
read_route(gchar * filename, gboolean is_local_net)
{
	gboolean ok = FALSE;
	FILE *in;

	connect_route *route = g_malloc(sizeof(connect_route));
	memset(route, 0, sizeof(connect_route));

	DEBUG(5) debugf("read_route, filename = %s\n", filename);

	route->filename = g_strdup(filename);
	route->name = g_strdup(filename);  /* quick hack */

	route->protocol = g_strdup("smtp");
	route->expand_h_sender_address = TRUE;

	route->is_local_net = is_local_net;

	route->do_pipelining = TRUE;

	if ((in = fopen(route->filename, "r")) == NULL) {
		logwrite(LOG_ALERT, "could not open route file %s: %s\n", route->filename, strerror(errno));
		g_free(route);
		return NULL;
	}

	gchar lval[256], rval[2048];
	while (read_statement(in, lval, 256, rval, 2048)) {
		if (strcmp(lval, "protocol") == 0)
			route->protocol = g_strdup(rval);
		else if (strcmp(lval, "mail_host") == 0)
			route->mail_host = parse_interface(rval, conf.remote_port);
		else if (strcmp(lval, "helo_name") == 0)
			route->helo_name = g_strdup(rval);
		else if (strcmp(lval, "wrapper") == 0)
			route->wrapper = g_strdup(rval);
		else if (strcmp(lval, "connect_error_fail") == 0)
			route->connect_error_fail = parse_boolean(rval);
		else if (strcmp(lval, "do_correct_helo") == 0)
			route->do_correct_helo = parse_boolean(rval);
		else if (strcmp(lval, "do_pipelining") == 0)
			route->do_pipelining = parse_boolean(rval);
		else if (strcmp(lval, "allowed_return_paths") == 0)
			route->allowed_return_paths = parse_address_list(rval, TRUE);
		else if (strcmp(lval, "allowed_mail_locals") == 0)
			route->allowed_mail_locals = parse_list(rval, TRUE);
		else if (strcmp(lval, "not_allowed_return_paths") == 0)
			route->not_allowed_return_paths = parse_address_list(rval, TRUE);
		else if (strcmp(lval, "not_allowed_mail_locals") == 0)
			route->not_allowed_mail_locals = parse_list(rval, TRUE);
		else if (strcmp(lval, "allowed_rcpt_domains") == 0)
			route->allowed_rcpt_domains = parse_list(rval, TRUE);
		else if (strcmp(lval, "not_allowed_rcpt_domains") == 0)
			route->not_allowed_rcpt_domains = parse_list(rval, TRUE);
		else if (strcmp(lval, "set_h_from_domain") == 0)
			route->set_h_from_domain = g_strdup(rval);
		else if (strcmp(lval, "set_h_reply_to_domain") == 0)
			route->set_h_reply_to_domain = g_strdup(rval);
		else if (strcmp(lval, "set_return_path_domain") == 0)
			route->set_return_path_domain = g_strdup(rval);
		else if (strcmp(lval, "map_return_path_addresses") == 0) {
			GList *node, *list;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				address *addr = create_address((gchar *) (pair->value), TRUE);
				g_free(pair->value);
				pair->value = (gpointer *) addr;
				route->map_return_path_addresses = g_list_append(route->map_return_path_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_from_addresses") == 0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_from_addresses = g_list_append(route->map_h_from_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_reply_to_addresses") == 0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_reply_to_addresses = g_list_append(route->map_h_reply_to_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "map_h_mail_followup_to_addresses") == 0) {
			GList *list, *node;

			list = parse_list(rval, TRUE);
			foreach(list, node) {
				gchar *item = (gchar *) (node->data);
				table_pair *pair = parse_table_pair(item, ':');
				route->map_h_mail_followup_to_addresses = g_list_append(route->map_h_mail_followup_to_addresses, pair);
				g_free(item);
			}
			g_list_free(list);
		} else if (strcmp(lval, "expand_h_sender_domain") == 0) {
			route->expand_h_sender_domain = parse_boolean(rval);
		} else if (strcmp(lval, "expand_h_sender_address") == 0) {
			route->expand_h_sender_address = parse_boolean(rval);
		} else if (strcmp(lval, "resolve_list") == 0)
			route->resolve_list = parse_resolve_list(rval);
		else if (strcmp(lval, "do_ssl") == 0) {
			/* we ignore this. This option is used by sqilconf */
			;
		}
#ifdef ENABLE_AUTH
		else if (strcmp(lval, "auth_name") == 0) {
			route->auth_name = g_strdup(rval);
		} else if (strcmp(lval, "auth_login") == 0) {
			route->auth_login = g_strdup(rval);
		} else if (strcmp(lval, "auth_secret") == 0) {
			route->auth_secret = g_strdup(rval);
		}
#else
		else if ((strcmp(lval, "auth_name") == 0)
		         || (strcmp(lval, "auth_login") == 0)
		         || (strcmp(lval, "auth_secret") == 0)) {
			logwrite(LOG_WARNING, "%s ignored: not compiled with auth support.\n", lval);
		}
#endif
		else if (strcmp(lval, "pop3_login") == 0) {
#ifdef ENABLE_POP3
			route->pop3_login = g_strdup(rval);
#else
			logwrite(LOG_WARNING, "pop3_login ignored: not compiled with pop support.\n");
#endif
		} else if (strcmp(lval, "pipe") == 0) {
			route->pipe = g_strdup(rval);
		} else if (strcmp(lval, "pipe_fromline") == 0) {
			route->pipe_fromline = parse_boolean(rval);
		} else if (strcmp(lval, "pipe_fromhack") == 0) {
			route->pipe_fromhack = parse_boolean(rval);
		} else if (strcmp(lval, "last_route") == 0) {
			route->last_route = parse_boolean(rval);
		} else
			logwrite(LOG_WARNING, "var '%s' not (yet) known, ignored\n", lval);
	}

	if (route->resolve_list == NULL) {
		if (is_local_net) {
			route->resolve_list = g_list_append(NULL, resolve_byname);
		} else {
#ifdef ENABLE_RESOLVER
			route->resolve_list = g_list_append(route->resolve_list, resolve_dns_mx);
			route->resolve_list = g_list_append(route->resolve_list, resolve_dns_a);
#endif
			route->resolve_list = g_list_append(route->resolve_list, resolve_byname);
		}
	}
	fclose(in);
	ok = TRUE;

	/* warn user about misconfigurations: */
	if ((route->map_h_from_addresses != NULL) && (route->set_h_from_domain != NULL)) {
		logwrite(LOG_WARNING, "'map_h_from_addresses' overrides 'set_h_from_domain'\n");
		g_free(route->set_h_from_domain);
		route->set_h_from_domain = NULL;
	}
	if ((route->map_h_reply_to_addresses != NULL) && (route->set_h_reply_to_domain != NULL)) {
		logwrite(LOG_WARNING, "'map_h_reply_to_addresses' overrides 'set_h_reply_to_domain'\n");
		g_free(route->set_h_reply_to_domain);
		route->set_h_reply_to_domain = NULL;
	}

	if (!ok) {
		g_free(route);
		route = NULL;
	}

	return route;
}

static void
_g_list_free_all(GList * list)
{
	GList *node;
	if (list) {
		foreach(list, node)
			g_free(node->data);
		g_list_free(list);
	}
}

void
destroy_route(connect_route * r)
{
	if (r->filename)
		g_free(r->filename);
	if (r->protocol)
		g_free(r->protocol);
	if (r->mail_host) {
		g_free(r->mail_host->address);
		g_free(r->mail_host);
	}
	if (r->wrapper)
		g_free(r->wrapper);
	if (r->helo_name)
		g_free(r->helo_name);
	_g_list_free_all(r->allowed_mail_locals);
	_g_list_free_all(r->not_allowed_mail_locals);
	_g_list_free_all(r->allowed_rcpt_domains);
	_g_list_free_all(r->not_allowed_rcpt_domains);
	if (r->set_h_from_domain)
		g_free(r->set_h_from_domain);
	if (r->set_h_reply_to_domain)
		g_free(r->set_h_reply_to_domain);
	if (r->set_return_path_domain)
		g_free(r->set_return_path_domain);
	if (r->map_h_reply_to_addresses)
		destroy_table(r->map_h_reply_to_addresses);
	if (r->resolve_list)
		g_list_free(r->resolve_list);
#ifdef ENABLE_AUTH
	if (r->auth_name)
		g_free(r->auth_name);
	if (r->auth_login)
		g_free(r->auth_login);
	if (r->auth_secret)
		g_free(r->auth_secret);
#endif
#ifdef ENABLE_POP3
	if (r->pop3_login)
		g_free(r->pop3_login);
#endif
	if (r->pipe)
		g_free(r->pipe);
	g_free(r);
}

GList*
read_route_list(GList * rf_list, gboolean is_local_net)
{
	GList *list = NULL;
	GList *node;
	uid_t saved_uid, saved_gid;

	if (!conf.run_as_user) {
		set_euidgid(0, 0, &saved_uid, &saved_gid);
	}

	foreach(rf_list, node) {
		gchar *fname = (gchar *) (node->data);
		connect_route *route = read_route(fname, is_local_net);
		if (route)
			list = g_list_append(list, route);
		else
			logwrite(LOG_ALERT, "could not read route configuration %s\n", fname);
	}

	/* set uid and gid back */
	if (!conf.run_as_user) {
		set_euidgid(saved_uid, saved_gid, NULL, NULL);
	}

	return list;
}

void
destroy_route_list(GList * list)
{
	GList *node;

	foreach(list, node) {
		connect_route *route = (connect_route *) (node->data);
		destroy_route(route);
	}
	g_list_free(list);
}

#ifdef ENABLE_POP3

get_conf*
read_get_conf(gchar * filename)
{
	FILE *in;

	get_conf *gc = g_malloc(sizeof(get_conf));
	memset(gc, 0, sizeof(get_conf));

	gc->server_port = 110;

	if ((in = fopen(filename, "r")) == NULL) {
		logwrite(LOG_ALERT, "could not open get file %s: %s\n", filename, strerror(errno));
		g_free(gc);
		return NULL;
	}

	gchar lval[256], rval[2048];
	while (read_statement(in, lval, 256, rval, 2048)) {
		if (strcmp(lval, "protocol") == 0)
			gc->protocol = g_strdup(rval);
		else if (strcmp(lval, "server") == 0)
			gc->server_name = g_strdup(rval);
		else if (strcmp(lval, "port") == 0)
			gc->server_port = atoi(rval);
		else if (strcmp(lval, "wrapper") == 0)
			gc->wrapper = g_strdup(rval);
		else if (strcmp(lval, "user") == 0)
			gc->login_user = g_strdup(rval);
		else if (strcmp(lval, "pass") == 0)
			gc->login_pass = g_strdup(rval);
		else if (strcmp(lval, "address") == 0)
			gc->address = create_address_qualified(rval, TRUE, conf.host_name);
		else if (strcmp(lval, "return_path") == 0)
			gc->return_path = create_address_qualified(rval, TRUE, conf.host_name);
		else if (strcmp(lval, "do_ssl") == 0)
			/* we ignore this. This option is used by sqilconf */
			;
		else if (strcmp(lval, "do_keep") == 0)
			gc->do_keep = parse_boolean(rval);
		else if (strcmp(lval, "do_uidl") == 0)
			gc->do_uidl = parse_boolean(rval);
		else if (strcmp(lval, "do_uidl_dele") == 0)
			gc->do_uidl_dele = parse_boolean(rval);
		else if (strcmp(lval, "max_size") == 0)
			gc->max_size = atoi(rval);
		else if (strcmp(lval, "max_size_delete") == 0)
			gc->max_size_delete = parse_boolean(rval);
		else if (strcmp(lval, "max_count") == 0)
			gc->max_count = atoi(rval);
		else if (strcmp(lval, "resolve_list") == 0)
			gc->resolve_list = parse_resolve_list(rval);
		else
			logwrite(LOG_WARNING, "var '%s' not (yet) known, ignored\n", lval);
	}
	fclose(in);

	if (gc->resolve_list == NULL) {
#ifdef ENABLE_RESOLVER
		gc->resolve_list = g_list_append(NULL, resolve_dns_a);
#endif
		gc->resolve_list = g_list_append(NULL, resolve_byname);
	}

	if (gc->protocol == NULL)
		gc->protocol = g_strdup("pop3");
	return gc;
}

void
destroy_get_conf(get_conf * gc)
{
	if (gc->protocol)
		g_free(gc->protocol);
	if (gc->server_name)
		g_free(gc->server_name);
	if (gc->login_user)
		g_free(gc->login_user);
	if (gc->login_pass)
		g_free(gc->login_pass);
	if (gc->wrapper)
		g_free(gc->wrapper);
	if (gc->address)
		destroy_address(gc->address);
	if (gc->return_path)
		destroy_address(gc->return_path);
	if (gc->resolve_list)
		g_list_free(gc->resolve_list);
	g_free(gc);
}

#endif

connect_route*
create_local_route()
{
	connect_route *route;

	route = g_malloc(sizeof(connect_route));
	if (!route) {
		return NULL;
	}
	memset(route, 0, sizeof(connect_route));
	route->protocol = g_strdup("smtp");
	route->is_local_net = TRUE;
	route->name = g_strdup("local_net (default)");
	route->expand_h_sender_address = TRUE;
	route->resolve_list = g_list_append(NULL, resolve_byname);
	route->connect_error_fail = TRUE;
	return route;
}
