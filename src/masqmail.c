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

/* mutually exclusive modes. Note that there is no 'queue daemon' mode.
   It, as well as the distinction beween the two (non exclusive) daemon
   (queue and listen) modes, is handled by flags.*/
typedef enum _mta_mode {
	MODE_NONE = 0,  /* for being able to check if a mode was defined */
	MODE_ACCEPT,  /* accept message on stdin */
	MODE_DAEMON,  /* run as daemon */
	MODE_RUNQUEUE,  /* single queue run, online or offline */
	MODE_SMTP,  /* accept SMTP on stdin */
	MODE_LIST,  /* list queue */
	MODE_MCMD,  /* do queue manipulation */
	MODE_VERSION,  /* show version */
	MODE_BI,  /* fake ;-) */
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

/*
argv: the original argv
argp: number of arg (may get modified!)
cp: pointing to the char after the option
    e.g.  `-d 6'     `-d6'
             ^          ^
*/
gchar*
get_optarg(char* argv[], gint* argp, char* cp)
{
	if (*cp) {
		/* this kind: -xval */
		return cp;
	}
	cp = argv[*argp+1];
	if (cp && (*cp != '-')) {
		/* this kind: -x val */
		(*argp)++;
		return cp;
	}
	return NULL;
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

/* on -bd or if -q has an argument */
static void
mode_daemon(gboolean do_listen, gint queue_interval, char *argv[])
{
	guint pid;

	/* daemon */
	if (!conf.run_as_user) {
		if ((conf.orig_uid != 0) && (conf.orig_uid != conf.mail_uid)) {
			fprintf(stderr, "must be root or %s for daemon.\n", DEF_MAIL_USER);
			exit(1);
		}
	}

	/* reparent to init only if init is not already the parent */
	if (getppid() != 1) {
		if ((pid = fork()) > 0) {
			exit(0);
		} else if (pid < 0) {
			logwrite(LOG_ALERT, "could not fork!\n");
			exit(1);
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

	logwrite(LOG_NOTICE, "%s %s daemon starting\n", PACKAGE, VERSION);
	listen_port(do_listen ? conf.listen_addresses : NULL, queue_interval, argv);
}

/* -bs or called as smtpd or in.smtpd */
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
		exit(1);

	smtp_in(stdin, stderr, peername, NULL);
}

/* default mode if address args or -t is specified, or called as rmail */
static void
mode_accept(address * return_path, gchar * full_sender_name, guint accept_flags, char **addresses, int addr_cnt)
{
	/* accept message on stdin */
	accept_error err;
	message *msg = create_message();
	gint i;

	if (return_path && !is_privileged_user(conf.orig_uid)) {
		fprintf(stderr, "must be root, %s or in group %s for setting return path.\n", DEF_MAIL_USER, DEF_MAIL_GROUP);
		exit(1);
	}

	if (!conf.run_as_user) {
		seteuid(conf.orig_uid);
		setegid(conf.orig_gid);
	}

	DEBUG(5) debugf("accepting message on stdin\n");

	msg->received_prot = PROT_LOCAL;
	for (i = 0; i < addr_cnt; i++) {
		if (addresses[i][0] == '|')
			logwrite(LOG_ALERT, "no pipe allowed as recipient address: %s\n", addresses[i]);
			exit(1);
		}
		msg->rcpt_list = g_list_append(msg->rcpt_list, create_address_qualified(addresses[i], TRUE, conf.host_name));
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
						exit(0);
					} else
						exit(1);
				} else if (pid < 0) {
					logwrite(LOG_ALERT, "could not fork for delivery, id = %s\n", msg->uid);
				}
			}
		} else {
			fprintf(stderr, "Could not write spool file\n");
			exit(1);
		}
	} else {
		switch (err) {
		case AERR_EOF:
			fprintf(stderr, "unexpected EOF.\n");
			exit(1);
		case AERR_NORCPT:
			fprintf(stderr, "no recipients.\n");
			exit(1);
		case AERR_SIZE:
			fprintf(stderr, "max message size exceeded.\n");
			exit(1);
		default:
			/* should never happen: */
			fprintf(stderr, "Unknown error (%d)\r\n", err);
			exit(1);
		}
		exit(1);
	}
}

/*
if -Mrm is given

currently only the `rm' command is supported
until this changes, we don't need any facility for further commands
return success if at least one message had been deleted
*/
static int
manipulate_queue(char* cmd, char* id[])
{
	gboolean ok = FALSE;

	if (strcmp(cmd, "rm") != 0) {
		fprintf(stderr, "unknown command %s\n", cmd);
		return FALSE;
	}

	set_euidgid(conf.mail_uid, conf.mail_gid, NULL, NULL);

	/* privileged users may delete any mail */
	if (is_privileged_user(conf.orig_uid)) {
		for (; *id; id++) {
			fprintf(stderr, "id: %s\n", *id);
			if (queue_delete(*id)) {
				ok = TRUE;
			}
		}
		return ok;
	}

	struct passwd *pw = getpwuid(conf.orig_uid);
	if (!pw) {
		fprintf(stderr, "could not find a passwd entry for uid %d: %s\n",
		        conf.orig_uid, strerror(errno));
		return FALSE;
	}

	/* non-privileged users may only delete their own messages */
	for (; *id; id++) {
		message *msg = msg_spool_read(*id, FALSE);

		fprintf(stderr, "id: %s\n", *id);

		if (!msg->ident) {
			fprintf(stderr, "message %s does not have an ident\n", *id);
			continue;
		}
		if (strcmp(pw->pw_name, msg->ident) != 0) {
			fprintf(stderr, "you do not own message id %s\n", *id);
			continue;
		}

		if ( (msg->received_host || (msg->received_prot != PROT_LOCAL))
#ifdef ENABLE_IDENT
		    && !is_in_netlist(msg->received_host, conf.ident_trusted_nets)
#endif
		) {
			fprintf(stderr, "message %s was not received locally or from a trusted network\n", *id);
			continue;
		}

		ok = queue_delete(*id);
	}
	return ok;
}

/* -qo, -q (without argument), or called as runq */
/* TODO: are -qo and -q exclusively or not?
         And how is this related to being a daemon? */
static int
run_queue(gboolean do_runq, gboolean do_runq_online, char* route_name)
{
	int ret;

	/* queue runs */
	set_identity(conf.orig_uid, "queue run");

	if (do_runq) {
		ret = queue_run();
	}

	if (do_runq_online) {
		if (route_name) {
			conf.online_detect = g_strdup("argument");
			set_online_name(route_name);
		}
		ret = queue_run_online();
	}
	return ret;
}

/* -bV or default mode if neither addr arg nor -t */
static void
mode_version(void)
{
	gchar *with_resolver = "";
	gchar *with_auth = "";
	gchar *with_ident = "";

#ifdef ENABLE_RESOLVER
	with_resolver = " +resolver";
#endif
#ifdef ENABLE_AUTH
	with_auth = " +auth";
#endif
#ifdef ENABLE_IDENT
	with_ident = " +ident";
#endif

	printf("%s %s%s%s%s\n", PACKAGE, VERSION, with_resolver, with_auth, with_ident);
}

int
main(int argc, char *argv[])
{
	gchar *progname;
	char* opt;
	gint arg;

	mta_mode mta_mode = MODE_NONE;
	gboolean do_listen = FALSE;
	gboolean do_runq = FALSE;
	gboolean do_runq_online = FALSE;
	gboolean do_queue = FALSE;
	gint queue_interval = 0;
	gchar *M_cmd = NULL;
	gboolean opt_t = FALSE;
	gboolean opt_i = FALSE;
	gchar *conf_file = CONF_FILE;
	gchar *route_name = NULL;
	gchar *f_address = NULL;
	address *return_path = NULL;  /* may be changed by -f option */
	gchar *full_sender_name = NULL;
	gboolean do_verbose = FALSE;
	gint debug_level = -1;

	/* strip the path part */
	progname = strrchr(argv[0], '/');
	progname = (progname) ? progname+1 : argv[0];

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
	for (arg=1; arg<argc && argv[arg][0]=='-'; arg++) {
		opt = argv[arg] + 1;  /* points to the char after the dash */

		if (strcmp(opt, "-") == 0) {
			/* everything after `--' are address arguments */
			arg++;
			break;

		} else if (strcmp(opt, "bd") == 0) {
			do_listen = TRUE;
			mta_mode = MODE_DAEMON;

		} else if (strcmp(opt, "bi") == 0) {
			/* ignored */
			mta_mode = MODE_BI;

		} else if (strcmp(opt, "bs") == 0) {
			mta_mode = MODE_SMTP;

		} else if (strcmp(opt, "bp") == 0) {
			mta_mode = MODE_LIST;

		} else if (strcmp(opt, "bV") == 0) {
			mta_mode = MODE_VERSION;

		} else if (strncmp(opt, "B", 1) == 0) {
			/* we ignore this and throw the argument away */
			get_optarg(argv, &arg, opt+1);

		} else if (strncmp(opt, "C", 1) == 0) {
			conf_file = get_optarg(argv, &arg, opt+1);
			if (!conf_file) {
				fprintf(stderr, "-C requires a filename as argument.\n");
				exit(1);
			}

		} else if (strncmp(opt, "d", 1) == 0) {
			if (getuid() != 0) {
				fprintf(stderr, "only root may set the debug level.\n");
				exit(1);
			}
			char *lvl = get_optarg(argv, &arg, opt+1);
			if (!lvl) {
				fprintf(stderr, "-d requires a number argument.\n");
				exit(1);
			}
			debug_level = atoi(lvl);

		} else if (strncmp(opt, "f", 1) == 0) {
			/* set return path */
			gchar *address = get_optarg(argv, &arg, opt+1);
			if (!address) {
				fprintf(stderr, "-f requires an address argument\n");
				exit(1);
			}
			f_address = g_strdup(address);

		} else if (strncmp(opt, "F", 1) == 0) {
			full_sender_name = get_optarg(argv, &arg, opt+1);
			if (!full_sender_name) {
				fprintf(stderr, "-F requires a name argument\n");
				exit(1);
			}

		} else if (strcmp(opt, "i") == 0) {
			opt_i = TRUE;

		} else if (strcmp(opt, "m") == 0) {
			/* ignore -m (me too) switch (see man page) */

		} else if (strcmp(opt, "Mrm") == 0) {
			mta_mode = MODE_MCMD;
			M_cmd = "rm";

		} else if (strcmp(opt, "odq") == 0) {
			do_queue = TRUE;

		} else if (strcmp(opt, "oi") == 0) {
			opt_i = TRUE;

		} else if (strncmp(opt, "o", 1) == 0) {
			/* ignore all other -oXXX options */

		} else if (strncmp(opt, "qo", 2) == 0) {
			mta_mode = MODE_RUNQUEUE;
			do_runq = FALSE;
			do_runq_online = TRUE;
			/* can be NULL, then we use online detection method */
			route_name = get_optarg(argv, &arg, opt+2);

		} else if (strncmp(opt, "q", 1) == 0) {
			/* must be after the `qo' check */
			gchar *optarg;

			do_runq = TRUE;
			mta_mode = MODE_RUNQUEUE;
			optarg = get_optarg(argv, &arg, opt+1);
			if (optarg) {
				/* not just one single queue run but regular runs */
				mta_mode = MODE_DAEMON;
				queue_interval = time_interval(optarg);
			}

		} else if (strcmp(opt, "t") == 0) {
			opt_t = TRUE;

		} else if (strcmp(opt, "v") == 0) {
			do_verbose = TRUE;

		} else {
			fprintf(stderr, "unrecognized option `-%s'\n", opt);
			exit(1);
		}
	}

	if (!mta_mode) {
		mta_mode = (arg<argc || opt_t) ? MODE_ACCEPT : MODE_VERSION;
	}

	if (mta_mode == MODE_VERSION) {
		mode_version();
		exit(0);
	}

	/* initialize random generator */
	srand(time(NULL));
	/* ignore SIGPIPE signal */
	signal(SIGPIPE, SIG_IGN);

	/* close all possibly open file descriptors, except std{in,out,err} */
	{
		int i, max_fd = sysconf(_SC_OPEN_MAX);

		if (max_fd <= 0) {
			max_fd = 64;
		}
		for (i=3; i<max_fd; i++) {
			close(i);
		}
	}

	init_conf();

	/* if we are not privileged, and the config file was changed we
	   implicetely set the the run_as_user flag and give up all
	   privileges.

	   So it is possible for a user to run his own daemon without
	   breaking security.
	 */
	if ((strcmp(conf_file, CONF_FILE) != 0) && (conf.orig_uid != 0)) {
		conf.run_as_user = TRUE;
		seteuid(conf.orig_uid);
		setegid(conf.orig_gid);
		setuid(conf.orig_uid);
		setgid(conf.orig_gid);
	}

	conf.log_dir = LOG_DIR;
	logopen();
	if (!read_conf(conf_file)) {
		logwrite(LOG_ALERT, "SHUTTING DOWN due to problems reading config\n");
		exit(5);
	}
	logclose();

	if (do_queue) {
		conf.do_queue = TRUE;
	}
	if (do_verbose) {
		conf.do_verbose = TRUE;
	}
	if (debug_level >= 0) {  /* if >= 0, it was given by argument */
		conf.debug_level = debug_level;
	}

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
			exit(1);
		}
		if (setuid(0) != 0) {
			fprintf(stderr, "could not gain root privileges. Is the setuid bit set? : %s\n", strerror(errno));
			exit(1);
		}
	}

	if (!logopen()) {
		fprintf(stderr, "could not open log file\n");
		exit(1);
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
			exit(1);
		}
	}

	switch (mta_mode) {
	case MODE_DAEMON:
		mode_daemon(do_listen, queue_interval, argv);
		break;

	case MODE_RUNQUEUE:
		exit(run_queue(do_runq, do_runq_online, route_name) ? 0 : 1);
		break;

	case MODE_SMTP:
		mode_smtp();
		break;

	case MODE_LIST:
		queue_list();
		break;

	case MODE_BI:
		exit(0);
		break;  /* well... */

	case MODE_MCMD:
		exit(manipulate_queue(M_cmd, &argv[arg]) ? 0 : 1);
		break;

	case MODE_ACCEPT:
		{
			guint accept_flags = (opt_t ? ACC_DEL_RCPTS | ACC_RCPT_FROM_HEAD : 0)
			                     | (opt_i ? ACC_DOT_IGNORE : ACC_NODOT_RELAX);
			mode_accept(return_path, full_sender_name, accept_flags, &(argv[arg]), argc - arg);
			exit(0);
		}
		break;

	default:
		fprintf(stderr, "unknown mode: %d\n", mta_mode);
		break;
	}

	logclose();

	exit(0);
}
