// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"

#include <pwd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>

/*
**  mutually exclusive modes. Note that there is no 'queue daemon' mode.
**  It, as well as the distinction beween the two (non exclusive) daemon
**  (queue and listen) modes, is handled by flags.
*/
enum mta_mode {
	MODE_NONE = 0,  /* to check if a mode was set */
	MODE_ACCEPT,  /* accept message on stdin (fallback mode) */
	MODE_DAEMON,  /* run as daemon */
	MODE_RUNQUEUE,  /* single queue run, online or offline */
	MODE_SMTP,  /* accept SMTP on stdin */
	MODE_LIST,  /* list queue */
	MODE_MCMD,  /* do queue manipulation */
	MODE_VERSION,  /* show version */
	MODE_BI,  /* fake ;-) */
};
enum mta_mode mta_mode = MODE_NONE;

char *pidfile = NULL;
volatile int sigterm_in_progress = 0;

static void
sigterm_handler(int sig)
{
	if (sigterm_in_progress)
		raise(sig);
	sigterm_in_progress = 1;

	if (pidfile) {
		uid_t uid = geteuid();
		if (seteuid(0) != 0) {
			logwrite(LOG_ALERT, "sigterm_handler: could not set "
					"euid to %d: %s\n",
					0, strerror(errno));
		}
		if (unlink(pidfile) != 0)
			logwrite(LOG_WARNING,
					"could not delete pid file %s: %s\n",
					pidfile, strerror(errno));
		seteuid(uid);  /* we exit anyway after this, just to be sure */
	}

	signal(sig, SIG_DFL);
	raise(sig);
}

/*
**  argv: the original argv
**  argp: number of arg (may get modified!)
**  cp: pointing to the char after the option
**    e.g.  `-d 6'     `-d6'
**             ^          ^
*/
gchar*
get_optarg(char *argv[], gint *argp, char *cp)
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

/*
** Create any missing directory in pathname `dir'. (Like `mkdir -p'.)
** The code is taken from nmh.
*/
gboolean
makedir_rec(char *dir, int perms)
{
	char path[PATH_MAX];
	char *cp, *c;
	int had_an_error = 0;
	mode_t savedmask;

	c = strncpy(path, dir, sizeof(path));

	savedmask = umask(0);

	while (!had_an_error && (c = strchr(c+1, '/'))) {
		*c = '\0';
		/* Create an outer directory. */
		if (mkdir(path, perms) == -1 && errno != EEXIST) {
			fprintf(stderr, "unable to create `%s': %s\n",
					path, strerror(errno));
			had_an_error = 1;
		}
		*c = '/';
	}

	/*
	** Create the innermost nested subdirectory of the
	** path we're being asked to create.
	*/
	if (!had_an_error && mkdir(dir, perms)==-1 && errno != EEXIST) {
		fprintf(stderr, "unable to create `%s': %s\n",
				dir, strerror(errno));
		had_an_error = 1;
	}
	umask(savedmask);

	return (had_an_error) ? 0 : 1;
}

gboolean
write_pidfile(gchar *name)
{
	FILE *fptr;

	if ((fptr = fopen(name, "wt"))) {
		fprintf(fptr, "%d\n", getpid());
		fclose(fptr);
		pidfile = strdup(name);
		return TRUE;
	}
	logwrite(LOG_WARNING, "could not write pid file: %s\n",
			strerror(errno));
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
			fprintf(stderr, "must be root or %s for daemon.\n",
					DEF_MAIL_USER);
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
	makedir_rec(PID_DIR, 0755);
	write_pidfile(PID_DIR "/masqmail.pid");

	conf.do_verbose = FALSE;

	/*
	**  closing and reopening the log ensures that it is open afterwards
	**  because it is possible that the log is assigned to fd 1 and gets
	**  thus closes by fclose(stdout). Similar for the debugfile.
	*/
	logclose();
	fclose(stdin);
	fclose(stdout);
	fclose(stderr);
	logopen();

	logwrite(LOG_NOTICE, "%s %s daemon starting\n", PACKAGE, VERSION);
	listen_port(do_listen ? conf.listen_addresses : NULL,
			queue_interval, argv);
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
		set_euidgid(conf.orig_uid, conf.orig_gid, NULL, NULL);
	}

	DEBUG(5) debugf("accepting smtp message on stdin\n");

	if (getpeername(0, (struct sockaddr *) (&saddr), &dummy) == 0) {
		peername = g_strdup(inet_ntoa(saddr.sin_addr));
	} else if (errno != ENOTSOCK)
		exit(1);

	smtp_in(stdin, stderr, peername, NULL);
}

/* default mode if address args or -t is specified */
static void
mode_accept(address *return_path, gchar *full_sender_name, guint accept_flags,
		char **addresses, int addr_cnt)
{
	/* accept message on stdin */
	accept_error err;
	message *msg = create_message();
	gint i;
	pid_t pid;

	if (return_path && !is_privileged_user(conf.orig_uid)) {
		fprintf(stderr, "must be root, %s or in group %s for "
				"setting return path.\n",
				DEF_MAIL_USER, DEF_MAIL_GROUP);
		exit(1);
	}

	if (!conf.run_as_user) {
		set_euidgid(conf.orig_uid, conf.orig_gid, NULL, NULL);
	}

	DEBUG(5) debugf("accepting message on stdin\n");

	msg->received_prot = PROT_LOCAL;

	/* warn if -t option and cmdline addr args */
	if (addr_cnt && (accept_flags & ACC_RCPT_FROM_HEAD)) {
		logwrite(LOG_ALERT, "command line address arguments are "
				"now *added*  to the mail header\\\n");
		logwrite(LOG_ALERT, "  recipient addresses (instead of "
				"substracted)  when -t is given.\\\n");
		logwrite(LOG_ALERT, "  this changed with version 0.3.1\n");
	}

	for (i = 0; i < addr_cnt; i++) {
		if (addresses[i][0] == '|') {
			logwrite(LOG_ALERT, "no pipe allowed as recipient "
					"address: %s\n", addresses[i]);
			/* should we better ignore this one addr? */
			exit(1);
		}
		msg->rcpt_list = g_list_append(msg->rcpt_list,
				create_address_qualified(addresses[i],
				TRUE, conf.host_name));
	}

	/* -f option */
	msg->return_path = return_path;

	/* -F option */
	msg->full_sender_name = full_sender_name;

	err = accept_message(stdin, msg, accept_flags);

	switch (err) {
	case AERR_OK:
		/* to continue; all other cases exit */
		break;
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

	if (!spool_write(msg, TRUE)) {
		fprintf(stderr, "Could not write spool file\n");
		exit(1);
	}

	/* here the mail is queued and thus in our responsibility */
	logwrite(LOG_NOTICE, "%s <= %s with %s\n", msg->uid,
			addr_string(msg->return_path), prot_names[PROT_LOCAL]);

	if (conf.do_queue) {
		/* we're finished as we only need to queue it */
		return;
	}

	/* deliver at once */
	if ((pid = fork()) < 0) {
		logwrite(LOG_ALERT, "could not fork for delivery, id = %s\n",
				msg->uid);
	} else if (pid == 0) {
		conf.do_verbose = FALSE;
		fclose(stdin);
		fclose(stdout);
		fclose(stderr);
		if (deliver(msg)) {
			exit(0);
		} else {
			/*
			**  TODO: Should we really fail here? Because the
			**  mail is queued already. If we fail the client
			**  might submit it again.  If at-once-delivery
			**  is seen as an additional best-effort service,
			**  then we should still exit successful here.
			*/
			exit(1);
		}
	}
}

/*
**  if -Mrm is given
**
**  currently only the `rm' command is supported
**  until this changes, we don't need any facility for further commands
**  return success if at least one message had been deleted
*/
static int
manipulate_queue(char *cmd, char *id[])
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
		fprintf(stderr, "could not find a passwd entry for "
				"uid %d: %s\n",
				conf.orig_uid, strerror(errno));
		return FALSE;
	}

	/* non-privileged users may only delete their own messages */
	for (; *id; id++) {
		message *msg = msg_spool_read(*id);

		fprintf(stderr, "id: %s\n", *id);

		if (!msg->ident) {
			fprintf(stderr, "message %s does not have an ident\n",
					*id);
			continue;
		}
		if (strcmp(pw->pw_name, msg->ident) != 0) {
			fprintf(stderr, "you do not own message id %s\n", *id);
			continue;
		}

		if (msg->received_host || (msg->received_prot != PROT_LOCAL)) {
			fprintf(stderr, "message %s was not received "
					"locally\n", *id);
			continue;
		}

		ok = queue_delete(*id);
	}
	return ok;
}

/* -qo, -q (without argument), or called as runq */
static int
run_queue(gboolean do_runq, gboolean do_runq_online, char *route_name)
{
	int ret;

	/* queue runs */
	set_identity(conf.orig_uid, "queue run");

	if (do_runq) {
		ret = queue_run();
	}

	if (do_runq_online) {
		if (route_name) {
			conf.online_query = g_strdup_printf("/bin/echo %s",
					route_name);
		}
		/*
		**  TODO: change behavior of `-qo without argument'?
		**  Because that behavior is included in -q.
		*/
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

#ifdef ENABLE_RESOLVER
	with_resolver = " +resolver";
#endif
#ifdef ENABLE_AUTH
	with_auth = " +auth";
#endif

	printf("%s %s%s%s\n", PACKAGE, VERSION, with_resolver, with_auth);
}

void
set_mode(enum mta_mode mode)
{
	if (mta_mode && mta_mode!=mode) {
		fprintf(stderr, "operation mode was already specified "
				"(%d vs. %d)\n", mta_mode, mode);
		exit(1);
	}

	mta_mode = mode;
	return;
}

int
main(int argc, char *argv[])
{
	gchar *progname;
	char *opt;
	gint arg;

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
	} else if (strcmp(progname, "newaliases") == 0) {
		mta_mode = MODE_BI;
	} else if (strcmp(progname, "runq") == 0) {
		mta_mode = MODE_RUNQUEUE;
		do_runq = TRUE;
	} else if (strcmp(progname, "smtpd") == 0
	           || strcmp(progname, "in.smtpd") == 0) {
		mta_mode = MODE_SMTP;
	}

	/* parse cmd line */
	for (arg=1; arg<argc && argv[arg][0]=='-'; arg++) {
		opt = argv[arg] + 1;  /* points to the char after the dash */

		if (strcmp(opt, "-") == 0) {
			/* everything after `--' are address arguments */
			arg++;
			break;

		} else if (strcmp(opt, "bm") == 0) {
			set_mode(MODE_ACCEPT);

		} else if (strcmp(opt, "bd") == 0) {
			set_mode(MODE_DAEMON);
			do_listen = TRUE;

		} else if (strcmp(opt, "bi") == 0) {
			set_mode(MODE_BI);

		} else if (strcmp(opt, "bs") == 0) {
			set_mode(MODE_SMTP);

		} else if (strcmp(opt, "bp") == 0) {
			set_mode(MODE_LIST);

		} else if (strcmp(opt, "bV") == 0) {
			set_mode(MODE_VERSION);

		} else if (strncmp(opt, "B", 1) == 0) {
			/* we ignore this and throw the argument away */
			get_optarg(argv, &arg, opt+1);

		} else if (strncmp(opt, "C", 1) == 0) {
			conf_file = get_optarg(argv, &arg, opt+1);
			if (!conf_file) {
				fprintf(stderr, "-C requires filename arg.\n");
				exit(1);
			}

		} else if (strncmp(opt, "d", 1) == 0) {
			if (getuid() != 0) {
				fprintf(stderr, "only root may set the "
						"debug level.\n");
				exit(1);
			}
			char *lvl = get_optarg(argv, &arg, opt+1);
			if (!lvl) {
				fprintf(stderr, "-d requires number arg.\n");
				exit(1);
			}
			debug_level = atoi(lvl);

		} else if (strncmp(opt, "f", 1) == 0) {
			/* set return path */
			gchar *address = get_optarg(argv, &arg, opt+1);
			if (!address) {
				fprintf(stderr, "-f requires address arg.\n");
				exit(1);
			}
			f_address = g_strdup(address);

		} else if (strncmp(opt, "F", 1) == 0) {
			full_sender_name = get_optarg(argv, &arg, opt+1);
			if (!full_sender_name) {
				fprintf(stderr, "-F requires name arg.\n");
				exit(1);
			}

		} else if (strcmp(opt, "i") == 0) {
			opt_i = TRUE;

		} else if (strcmp(opt, "m") == 0) {
			/* ignore -m (me too) switch (see man page) */

		} else if (strcmp(opt, "Mrm") == 0) {
			set_mode(MODE_MCMD);
			M_cmd = "rm";

		} else if (strcmp(opt, "odq") == 0) {
			do_queue = TRUE;

		} else if (strcmp(opt, "oi") == 0) {
			opt_i = TRUE;

		} else if (strncmp(opt, "o", 1) == 0) {
			/* ignore all other -oXXX options */

		} else if (strncmp(opt, "qo", 2) == 0) {
			/* must be before the `q' check */
			set_mode(MODE_RUNQUEUE);
			do_runq_online = TRUE;
			/* can be NULL, then we use online detection method */
			/* TODO: behavior might change if it is NULL */
			route_name = get_optarg(argv, &arg, opt+2);
			if (!route_name) {
				fprintf(stderr, "Please do not use -qo "
						"without argument anymore; "
						"use -q instead.\n");
				fprintf(stderr, "The behavior for -qo without "
						"argument is likely to "
						"change.\n");
			}

		} else if (strncmp(opt, "q", 1) == 0) {
			/* must be after the `qo' check */
			gchar *optarg;

			optarg = get_optarg(argv, &arg, opt+1);
			if (optarg) {
				/* do regular queue runs */
				set_mode(MODE_DAEMON);
				queue_interval = time_interval(optarg);
			} else {
				/* do a single queue run */
				set_mode(MODE_RUNQUEUE);
				do_runq = TRUE;
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

	if (!mta_mode && arg==argc && !opt_t) {
		/*
		**  In this case no rcpts can be found, thus no mail
		**  can be sent, thus masqmail will always fail. We
		**  rather do something better instead. This covers
		**  also the case of calling masqmail without args.
		*/
		mode_version();
		exit(0);
	}

	if (mta_mode == MODE_VERSION) {
		mode_version();
		exit(0);
	}

	if (!mta_mode) {
		mta_mode = MODE_ACCEPT;
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

	/*
	**  if we are not privileged, and the config file was changed we
	**  implicetely set the the run_as_user flag and give up all
	**  privileges.
	**
	**  So it is possible for a user to run his own daemon without
	**  breaking security.
	*/
	if ((strcmp(conf_file, CONF_FILE) != 0) && (conf.orig_uid != 0)) {
		logwrite(LOG_NOTICE, "Changing to run_as_user.\n");
		conf.run_as_user = TRUE;
		set_euidgid(conf.orig_uid, conf.orig_gid, NULL, NULL);
		if (setgid(conf.orig_gid)) {
			logwrite(LOG_ALERT, "could not set gid to %d: %s\n",
					conf.orig_gid, strerror(errno));
			exit(1);
		}
		if (setuid(conf.orig_uid)) {
			logwrite(LOG_ALERT, "could not set uid to %d: %s\n",
					conf.orig_uid, strerror(errno));
			exit(1);
		}
	}

	conf.log_dir = LOG_DIR;
	conf.debug_level = debug_level;  /* for debuggin during read_conf() */
	/* FIXME: fails if we run as user */
	logopen();
	if (!read_conf(conf_file)) {
		logwrite(LOG_ALERT, "SHUTTING DOWN due to problems reading "
				"config\n");
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

	/*
	**  It appears that changing to / ensures that we are never in
	**  a directory which we cannot access. This situation could be
	**  possible after changing identity.
	**  Maybe we should only change to / if we not run as user, to
	**  allow relative paths for log files in test setups for
	**  instance.
	*/
	chdir("/");

	if (!conf.run_as_user) {
		if (setgid(0) != 0) {
			fprintf(stderr, "could not set gid to 0. "
					"Is the setuid bit set? : %s\n",
					strerror(errno));
			exit(1);
		}
		if (setuid(0) != 0) {
			fprintf(stderr, "could not gain root privileges. "
					"Is the setuid bit set? : %s\n",
					strerror(errno));
			exit(1);
		}
	}

	if (conf.run_as_user) {
		logwrite(LOG_NOTICE, "Using spool directory `%s' for "
				"lock files.\n", conf.spool_dir);
		conf.lock_dir = conf.spool_dir;
		makedir_rec(conf.spool_dir, 0755);
		makedir_rec(conf.log_dir, 0755);
	} else {
		makedir_rec(conf.lock_dir, 0775);
		chown(conf.lock_dir, conf.mail_uid, conf.mail_gid);
		makedir_rec(conf.spool_dir, 0755);
		chown(conf.spool_dir, conf.mail_uid, conf.mail_gid);
		makedir_rec(conf.log_dir, 0755);
		chown(conf.log_dir, conf.mail_uid, conf.mail_gid);
	}

	if (!logopen()) {
		fprintf(stderr, "could not open log file\n");
		exit(1);
	}

	DEBUG(1) debugf("----STARTING---- masqmail %s\n", VERSION);

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
		return_path = create_address_qualified(f_address, TRUE,
				conf.host_name);
		g_free(f_address);
		if (!return_path) {
			fprintf(stderr, "invalid RFC821 address: %s\n",
					f_address);
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
			guint accept_flags = 0;
			accept_flags |= (opt_t ? ACC_RCPT_FROM_HEAD : 0);
			accept_flags |= (opt_i ?
					ACC_DOT_IGNORE : ACC_NODOT_RELAX);
			mode_accept(return_path, full_sender_name,
					accept_flags, argv + arg, argc - arg);
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
