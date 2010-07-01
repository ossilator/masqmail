/*  MasqMail
    Copyright (C) 1999-2001 Oliver Kurth
    Copyright (C) 2010 markus schnalke <meillo@marmaro.de>

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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>

#include <glib.h>

#include "masqmail.h"

/* mutually exclusive modes. Note that there is neither a 'get' mode
   nor a 'queue daemon' mode. These, as well as the distinction beween
   the two (non exclusive) daemon (queue and listen) modes are handled
   by flags.*/
typedef enum _mta_mode {
	MODE_ACCEPT = 0,  /* accept message on stdin */
	MODE_DAEMON,  /* run as daemon */
	MODE_RUNQUEUE,  /* single queue run, online or offline */
	MODE_GET_DAEMON,  /* run as get (retrieve) daemon */
	MODE_SMTP,  /* accept SMTP on stdin */
	MODE_LIST,  /* list queue */
	MODE_MCMD,  /* do queue manipulation */
	MODE_VERSION,  /* show version */
	MODE_BI,  /* fake ;-) */
	MODE_NONE  /* to prevent default MODE_ACCEPT */
} mta_mode;

char *pidfile = NULL;
volatile int sigterm_in_progress = 0;

static void
sigterm_handler(int sig)
{
	if (sigterm_in_progress)
		raise(sig);
	sigterm_in_progress = 1;

	if (pidfile) {
		uid_t uid;
		uid = seteuid(0);
		if (unlink(pidfile) != 0)
			logwrite(LOG_WARNING, "could not delete pid file %s: %s\n", pidfile, strerror(errno));
		seteuid(uid);  /* we exit anyway after this, just to be sure */
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

#ifdef ENABLE_IDENT  /* so far used for that only */
static gboolean
is_in_netlist(gchar * host, GList * netlist)
{
	guint hostip = inet_addr(host);
	struct in_addr addr;

	addr.s_addr = hostip;
	if (addr.s_addr != INADDR_NONE) {
		GList *node;
		foreach(netlist, node) {
			struct in_addr *net = (struct in_addr *) (node->data);
			if ((addr.s_addr & net->s_addr) == net->s_addr)
				return TRUE;
		}
	}
	return FALSE;
}
#endif

gchar*
get_optarg(char *argv[], gint argc, gint * argp, gint * pos)
{
	if (argv[*argp][*pos])
		return &(argv[*argp][*pos]);
	else {
		if (*argp + 1 < argc) {
			if (argv[(*argp) + 1][0] != '-') {
				(*argp)++;
				*pos = 0;
				return &(argv[*argp][*pos]);
			}
		}
	}
	return NULL;
}

gchar*
get_progname(gchar * arg0)
{
	gchar *p = arg0 + strlen(arg0) - 1;
	while (p > arg0) {
		if (*p == '/')
			return p + 1;
		p--;
	}
	return p;
}

gboolean
write_pidfile(gchar * name)
{
	FILE *fptr;

	if ((fptr = fopen(name, "wt"))) {
		fprintf(fptr, "%d\n", getpid());
		fclose(fptr);
		pidfile = strdup(name);
		return TRUE;
	}
	logwrite(LOG_WARNING, "could not write pid file: %s\n", strerror(errno));
	return FALSE;
}

static void
mode_daemon(gboolean do_listen, gint queue_interval, char *argv[])
{
	guint pid;

	/* daemon */
	if (!conf.run_as_user) {
		if ((conf.orig_uid != 0) && (conf.orig_uid != conf.mail_uid)) {
			fprintf(stderr, "must be root or %s for daemon.\n", DEF_MAIL_USER);
			exit(EXIT_FAILURE);
		}
	}

	/* reparent to init only if init is not already the parent */
	if (getppid() != 1) {
		if ((pid = fork()) > 0) {
			exit(EXIT_SUCCESS);
		} else if (pid < 0) {
			logwrite(LOG_ALERT, "could not fork!");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGTERM, sigterm_handler);
	write_pidfile(PIDFILEDIR "/masqmail.pid");

	conf.do_verbose = FALSE;

	/* closing and reopening the log ensures that it is open afterwards
	   because it is possible that the log is assigned to fd 1 and gets
	   thus closes by fclose(stdout). Similar for the debugfile.
	*/
	logclose();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	logopen();

	listen_port(do_listen ? conf.listen_addresses : NULL, queue_interval, argv);
}

#ifdef ENABLE_POP3
static void
mode_get_daemon(gint get_interval, char *argv[])
{
	guint pid;

	/* daemon */
	if (!conf.run_as_user) {
		if ((conf.orig_uid != 0) && (conf.orig_uid != conf.mail_uid)) {
			fprintf(stderr, "must be root or %s for daemon.\n", DEF_MAIL_USER);
			exit(EXIT_FAILURE);
		}
	}

	/* reparent to init only if init is not already the parent */
	if (getppid() != 1) {
		if ((pid = fork()) > 0) {
			exit(EXIT_SUCCESS);
		} else if (pid < 0) {
			logwrite(LOG_ALERT, "could not fork!");
			exit(EXIT_FAILURE);
		}
	}

	signal(SIGTERM, sigterm_handler);
	write_pidfile(PIDFILEDIR "/masqmail-get.pid");

	conf.do_verbose = FALSE;

	/* closing and reopening the log ensures that it is open afterwards
	   because it is possible that the log is assigned to fd 1 and gets
	   thus closes by fclose(stdout). Similar for the debugfile.
	*/
	logclose();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	logopen();

	get_daemon(get_interval, argv);
}
#endif

#ifdef ENABLE_SMTP_SERVER
static void
mode_smtp()
{
	/* accept smtp message on stdin */
	/* write responses to stderr. */

	struct sockaddr_in saddr;
	gchar *peername = NULL;
	int dummy = sizeof(saddr);

	conf.do_verbose = FALSE;

	if (!conf.run_as_user) {
		seteuid(conf.orig_uid);
		setegid(conf.orig_gid);
	}

	DEBUG(5) debugf("accepting smtp message on stdin\n");

	if (getpeername(0, (struct sockaddr *) (&saddr), &dummy) == 0) {
		peername = g_strdup(inet_ntoa(saddr.sin_addr));
	} else if (errno != ENOTSOCK)
		exit(EXIT_FAILURE);

	smtp_in(stdin, stderr, peername, NULL);
}
#endif

static void
mode_accept(address * return_path, gchar * full_sender_name, guint accept_flags, char **addresses, int addr_cnt)
{
	/* accept message on stdin */
	accept_error err;
	message *msg = create_message();
	gint i;

	if (return_path && !is_privileged_user(conf.orig_uid)) {
		fprintf(stderr, "must be root, %s or in group %s for setting return path.\n", DEF_MAIL_USER, DEF_MAIL_GROUP);
		exit(EXIT_FAILURE);
	}

	if (!conf.run_as_user) {
		seteuid(conf.orig_uid);
		setegid(conf.orig_gid);
	}

	DEBUG(5) debugf("accepting message on stdin\n");

	msg->received_prot = PROT_LOCAL;
	for (i = 0; i < addr_cnt; i++) {
		if (addresses[i][0] != '|')
			msg->rcpt_list = g_list_append(msg->rcpt_list, create_address_qualified(addresses[i], TRUE, conf.host_name));
		else {
			logwrite(LOG_ALERT, "no pipe allowed as recipient address: %s\n", addresses[i]);
			exit(EXIT_FAILURE);
		}
	}

	/* -f option */
	msg->return_path = return_path;

	/* -F option */
	msg->full_sender_name = full_sender_name;

	if ((err = accept_message(stdin, msg, accept_flags)) == AERR_OK) {
		if (spool_write(msg, TRUE)) {
			pid_t pid;
			logwrite(LOG_NOTICE, "%s <= %s with %s\n", msg->uid, addr_string(msg->return_path), prot_names[PROT_LOCAL]);

			if (!conf.do_queue) {
				if ((pid = fork()) == 0) {
					conf.do_verbose = FALSE;
					fclose(stdin);
					fclose(stdout);
					fclose(stderr);
					if (deliver(msg)) {
						exit(EXIT_SUCCESS);
					} else
						exit(EXIT_FAILURE);
				} else if (pid < 0) {
					logwrite(LOG_ALERT, "could not fork for delivery, id = %s", msg->uid);
				}
			}
		} else {
			fprintf(stderr, "Could not write spool file\n");
			exit(EXIT_FAILURE);
		}
	} else {
		switch (err) {
		case AERR_EOF:
			fprintf(stderr, "unexpected EOF.\n");
			exit(EXIT_FAILURE);
		case AERR_NORCPT:
			fprintf(stderr, "no recipients.\n");
			exit(EXIT_FAILURE);
		case AERR_SIZE:
			fprintf(stderr, "max message size exceeded.\n");
			exit(EXIT_FAILURE);
		default:
			/* should never happen: */
			fprintf(stderr, "Unknown error (%d)\r\n", err);
			exit(EXIT_FAILURE);
		}
		exit(EXIT_FAILURE);
	}
}

int
main(int argc, char *argv[])
{
	/* cmd line flags */
	gchar *conf_file = CONF_FILE;
	gint arg = 1;
	gboolean do_get = FALSE;
	gboolean do_get_online = FALSE;

	gboolean do_listen = FALSE;
	gboolean do_runq = FALSE;
	gboolean do_runq_online = FALSE;

	gboolean do_queue = FALSE;

	gboolean do_verbose = FALSE;
	gint debug_level = -1;

	mta_mode mta_mode = MODE_ACCEPT;

	gint queue_interval = 0;
	gint get_interval = 0;
	gboolean opt_t = FALSE;
	gboolean opt_i = FALSE;
	gboolean opt_odb = FALSE;
	gboolean opt_oem = FALSE;
	gboolean exit_failure = FALSE;

	gchar *M_cmd = NULL;

	gint exit_code = EXIT_SUCCESS;
	gchar *route_name = NULL;
	gchar *get_name = NULL;
	gchar *progname;
	gchar *f_address = NULL;
	gchar *full_sender_name = NULL;
	address *return_path = NULL;  /* may be changed by -f option */

	progname = get_progname(argv[0]);

	if (strcmp(progname, "mailq") == 0) {
		mta_mode = MODE_LIST;
	} else if (strcmp(progname, "mailrm") == 0) {
		mta_mode = MODE_MCMD;
		M_cmd = "rm";
	} else if (strcmp(progname, "runq") == 0) {
		mta_mode = MODE_RUNQUEUE;
		do_runq = TRUE;
	} else if (strcmp(progname, "rmail") == 0) {
		/* the `rmail' alias should probably be removed now
		   that we have the rmail script. But let's keep it
		   for some while for compatibility. 2010-06-19 */
		mta_mode = MODE_ACCEPT;
		opt_i = TRUE;
	} else if (strcmp(progname, "smtpd") == 0 || strcmp(progname, "in.smtpd") == 0) {
		mta_mode = MODE_SMTP;
	}

	/* parse cmd line */
	while (arg < argc) {
		gint pos = 0;
		if ((argv[arg][pos] == '-') && (argv[arg][pos + 1] != '-')) {
			pos++;
			switch (argv[arg][pos++]) {
			case 'b':
				switch (argv[arg][pos++]) {
				case 'd':
					do_listen = TRUE;
					mta_mode = MODE_DAEMON;
					break;
				case 'i':
					/* ignored */
					mta_mode = MODE_BI;
					break;
				case 's':
					mta_mode = MODE_SMTP;
					break;
				case 'p':
					mta_mode = MODE_LIST;
					break;
				case 'V':
					mta_mode = MODE_VERSION;
					break;
				default:
					fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'B':
				/* we ignore this and throw the argument away */
				get_optarg(argv, argc, &arg, &pos);
				break;
			case 'C':
				if (!(conf_file = get_optarg(argv, argc, &arg, &pos))) {
					fprintf(stderr, "-C requires a filename as argument.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'F':
				{
					full_sender_name = get_optarg(argv, argc, &arg, &pos);
					if (!full_sender_name) {
						fprintf(stderr, "-F requires a name as an argument\n");
						exit(EXIT_FAILURE);
					}
				}
				break;
			case 'd':
				if (getuid() == 0) {
					char *lvl = get_optarg(argv, argc, &arg, &pos);
					if (lvl)
						debug_level = atoi(lvl);
					else {
						fprintf(stderr, "-d requires a number as an argument.\n");
						exit(EXIT_FAILURE);
					}
				} else {
					fprintf(stderr, "only root may set the debug level.\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'f':
				/* set return path */
				{
					gchar *address;
					address = get_optarg(argv, argc, &arg, &pos);
					if (address) {
						f_address = g_strdup(address);
					} else {
						fprintf(stderr, "-f requires an address as an argument\n");
						exit(EXIT_FAILURE);
					}
				}
				break;
			case 'g':
				do_get = TRUE;
				if (!mta_mode)
					mta_mode = MODE_NONE;  /* to prevent default MODE_ACCEPT */
				if (argv[arg][pos] == 'o') {
					pos++;
					do_get_online = TRUE;
					/* can be NULL, then we use online detection method */
					route_name = get_optarg(argv, argc, &arg, &pos);

					if (route_name != NULL) {
						if (isdigit(route_name[0])) {
							get_interval = time_interval(route_name, &pos);
							route_name = get_optarg(argv, argc, &arg, &pos);
							mta_mode = MODE_GET_DAEMON;
							do_get = FALSE;
						}
					}
				} else {
					if ((optarg = get_optarg(argv, argc, &arg, &pos))) {
						get_name = get_optarg(argv, argc, &arg, &pos);
					}
				}
				break;
			case 'i':
				if (argv[arg][pos] == 0) {
					opt_i = TRUE;
					exit_failure = FALSE;  /* may override -oem */
				} else {
					fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'M':
				{
					mta_mode = MODE_MCMD;
					M_cmd = g_strdup(&(argv[arg][pos]));
				}
				break;
			case 'o':
				switch (argv[arg][pos++]) {
				case 'e':
					if (argv[arg][pos++] == 'm')  /* -oem */
						if (!opt_i)
							exit_failure = TRUE;
					opt_oem = TRUE;
					break;
				case 'd':
					if (argv[arg][pos] == 'b')  /* -odb */
						opt_odb = TRUE;
					else if (argv[arg][pos] == 'q')  /* -odq */
						do_queue = TRUE;
					break;
				case 'i':
					opt_i = TRUE;
					exit_failure = FALSE;  /* may override -oem */
					break;
				}
				break;

			case 'q':
				{
					gchar *optarg;

					do_runq = TRUE;
					mta_mode = MODE_RUNQUEUE;
					if (argv[arg][pos] == 'o') {
						pos++;
						do_runq = FALSE;
						do_runq_online = TRUE;
						/* can be NULL, then we use online detection method */
						route_name = get_optarg(argv, argc, &arg, &pos);
					} else
						if ((optarg = get_optarg(argv, argc, &arg, &pos))) {
						mta_mode = MODE_DAEMON;
						queue_interval = time_interval(optarg, &pos);
					}
				}
				break;
			case 't':
				if (argv[arg][pos] == 0) {
					opt_t = TRUE;
				} else {
					fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
					exit(EXIT_FAILURE);
				}
				break;
			case 'v':
				do_verbose = TRUE;
				break;
			default:
				fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
				exit(EXIT_FAILURE);
			}
		} else {
			if (argv[arg][pos + 1] == '-') {
				if (argv[arg][pos + 2] != '\0') {
					fprintf(stderr, "unrecognized option '%s'\n", argv[arg]);
					exit(EXIT_FAILURE);
				}
				arg++;
			}
			break;
		}
		arg++;
	}

	if (mta_mode == MODE_VERSION) {
		gchar *with_resolver = "";
		gchar *with_smtp_server = "";
		gchar *with_pop3 = "";
		gchar *with_auth = "";
		gchar *with_maildir = "";
		gchar *with_ident = "";
		gchar *with_mserver = "";

#ifdef ENABLE_RESOLVER
		with_resolver = " +resolver";
#endif
#ifdef ENABLE_SMTP_SERVER
		with_smtp_server = " +smtp-server";
#endif
#ifdef ENABLE_POP3
		with_pop3 = " +pop3";
#endif
#ifdef ENABLE_AUTH
		with_auth = " +auth";
#endif
#ifdef ENABLE_MAILDIR
		with_maildir = " +maildir";
#endif
#ifdef ENABLE_IDENT
		with_ident = " +ident";
#endif
#ifdef ENABLE_MSERVER
		with_mserver = " +mserver";
#endif

		printf("%s %s%s%s%s%s%s%s%s\n", PACKAGE, VERSION, with_resolver, with_smtp_server,
		       with_pop3, with_auth, with_maildir, with_ident, with_mserver);

		exit(EXIT_SUCCESS);
	}

	/* initialize random generator */
	srand(time(NULL));
	/* ignore SIGPIPE signal */
	signal(SIGPIPE, SIG_IGN);

	/* close all possibly open file descriptors, except std{in,out,err} */
	{
		int i, max_fd = sysconf(_SC_OPEN_MAX);

		if (max_fd <= 0)
			max_fd = 64;
		for (i = 3; i < max_fd; i++)
			close(i);
	}

	init_conf();

	/* if we are not privileged, and the config file was changed we
	   implicetely set the the run_as_user flag and give up all
	   privileges.

	   So it is possible for a user to run his own daemon without
	   breaking security.
	 */
	if (strcmp(conf_file, CONF_FILE) != 0) {
		if (conf.orig_uid != 0) {
			conf.run_as_user = TRUE;
			seteuid(conf.orig_uid);
			setegid(conf.orig_gid);
			setuid(conf.orig_uid);
			setgid(conf.orig_gid);
		}
	}

	read_conf(conf_file);

	if (do_queue)
		conf.do_queue = TRUE;
	if (do_verbose)
		conf.do_verbose = TRUE;
	if (debug_level >= 0)  /* if >= 0, it was given by argument */
		conf.debug_level = debug_level;

	/* It appears that changing to / ensures that we are never in
	   a directory which we cannot access. This situation could be
	   possible after changing identity.
	   Maybe we should only change to / if we not run as user, to
	   allow relative paths for log files in test setups for
	   instance.
	*/
	chdir("/");

	if (!conf.run_as_user) {
		if (setgid(0) != 0) {
			fprintf(stderr, "could not set gid to 0. Is the setuid bit set? : %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		if (setuid(0) != 0) {
			fprintf(stderr, "could not gain root privileges. Is the setuid bit set? : %s\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (!logopen()) {
		fprintf(stderr, "could not open log file\n");
		exit(EXIT_FAILURE);
	}

	DEBUG(1) debugf("masqmail %s starting\n", VERSION);

	DEBUG(5) {
		gchar **str = argv;
		debugf("args: \n");
		while (*str) {
			debugf("%s \n", *str);
			str++;
		}
	}
	DEBUG(5) debugf("queue_interval = %d\n", queue_interval);

	if (f_address) {
		return_path = create_address_qualified(f_address, TRUE, conf.host_name);
		g_free(f_address);
		if (!return_path) {
			fprintf(stderr, "invalid RFC821 address: %s\n", f_address);
			exit(EXIT_FAILURE);
		}
	}

	if (do_get) {
#ifdef ENABLE_POP3
		if ((mta_mode == MODE_NONE) || (mta_mode == MODE_RUNQUEUE)) {
			set_identity(conf.orig_uid, "getting mail");
			if (do_get_online) {
				if (route_name != NULL) {
					conf.online_detect = g_strdup("argument");
					set_online_name(route_name);
				}
				get_online();
			} else {
				if (get_name)
					get_from_name(get_name);
				else
					get_all();
			}
		} else {
			logwrite(LOG_ALERT, "get (-g) only allowed alone or together with queue run (-q)\n");
		}
#else
		fprintf(stderr, "get (pop) support not compiled in\n");
#endif
	}

	switch (mta_mode) {
	case MODE_DAEMON:
		mode_daemon(do_listen, queue_interval, argv);
		break;
	case MODE_RUNQUEUE:
		{
			/* queue runs */
			set_identity(conf.orig_uid, "queue run");

			if (do_runq)
				exit_code = queue_run() ? EXIT_SUCCESS : EXIT_FAILURE;

			if (do_runq_online) {
				if (route_name != NULL) {
					conf.online_detect = g_strdup("argument");
					set_online_name(route_name);
				}
				exit_code =
					queue_run_online() ? EXIT_SUCCESS : EXIT_FAILURE;
			}
		}
		break;
	case MODE_GET_DAEMON:
#ifdef ENABLE_POP3
		if (route_name != NULL) {
			conf.online_detect = g_strdup("argument");
			set_online_name(route_name);
		}
		mode_get_daemon(get_interval, argv);
#endif
		break;

	case MODE_SMTP:
#ifdef ENABLE_SMTP_SERVER
		mode_smtp();
#else
		fprintf(stderr, "smtp server support not compiled in\n");
#endif
		break;

	case MODE_LIST:
		queue_list();
		break;

	case MODE_BI:
		exit(EXIT_SUCCESS);
		break;  /* well... */

	case MODE_MCMD:
		if (strcmp(M_cmd, "rm") == 0) {
			gboolean ok = FALSE;

			set_euidgid(conf.mail_uid, conf.mail_gid, NULL, NULL);

			if (is_privileged_user(conf.orig_uid)) {
				for (; arg < argc; arg++) {
					if (queue_delete(argv[arg]))
						ok = TRUE;
				}
			} else {
				struct passwd *pw = getpwuid(conf.orig_uid);
				if (pw) {
					for (; arg < argc; arg++) {
						message *msg = msg_spool_read(argv[arg], FALSE);
#ifdef ENABLE_IDENT
						if (((msg->received_host == NULL) && (msg->received_prot == PROT_LOCAL))
						    || is_in_netlist(msg->received_host, conf.ident_trusted_nets)) {
#else
						if ((msg->received_host == NULL) && (msg->received_prot == PROT_LOCAL)) {
#endif
							if (msg->ident) {
								if (strcmp(pw->pw_name, msg->ident) == 0) {
									if (queue_delete(argv[arg]))
										ok = TRUE;
								} else {
									fprintf(stderr, "you do not own message id %s\n", argv[arg]);
								}
							} else
								fprintf(stderr, "message %s does not have an ident.\n", argv[arg]);
						} else {
							fprintf(stderr, "message %s was not received locally or from a trusted network.\n", argv[arg]);
						}
					}
				} else {
					fprintf(stderr, "could not find a passwd entry for uid %d: %s\n", conf.orig_uid, strerror(errno));
				}
			}
			exit(ok ? EXIT_SUCCESS : EXIT_FAILURE);
		} else {
			fprintf(stderr, "unknown command %s\n", M_cmd);
			exit(EXIT_FAILURE);
		}
		break;

	case MODE_ACCEPT:
		{
			guint accept_flags = (opt_t ? ACC_DEL_RCPTS | ACC_RCPT_FROM_HEAD : 0)
			                     | (opt_i ? ACC_DOT_IGNORE : ACC_NODOT_RELAX);
			mode_accept(return_path, full_sender_name, accept_flags, &(argv[arg]), argc - arg);
			exit(exit_failure ? EXIT_FAILURE : EXIT_SUCCESS);
		}
		break;
	case MODE_NONE:
		break;
	default:
		fprintf(stderr, "unknown mode: %d\n", mta_mode);
		break;
	}

	logclose();

	exit(exit_code);
}
