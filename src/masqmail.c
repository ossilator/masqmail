// SPDX-FileCopyrightText: (C) 1999-2001 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "masqmail.h"
#include "whereami.h"

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
static enum mta_mode mta_mode = MODE_NONE;

static char *pidfile = NULL;
static volatile int sigterm_in_progress = 0;

static void
sigterm_handler(int sig)
{
	if (sigterm_in_progress)
		raise(sig);
	sigterm_in_progress = 1;

	if (pidfile) {
		acquire_root();
		if (unlink(pidfile) != 0)
			logerrno(LOG_WARNING, "could not delete pid file %s", pidfile);
		drop_root();  // we exit anyway after this, but whatever
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
static gchar*
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

static void
makedir(char *dir, gboolean reown)
{
	if (!mkdir(dir, 0755)) {
		chmod(dir, 0755);  // override possible umask
		if (reown && !conf.run_as_user) {
			chown(dir, conf.mail_uid, conf.mail_gid);
		}
		return;
	}
	if (errno == EEXIST) {
		return;
	}
	fprintf(stderr, "unable to create `%s': %s\n", dir, strerror(errno));
	exit(1);
}

static gboolean
write_pidfile(pid_t pid)
{
	FILE *fptr;
	gboolean ok = FALSE;

	acquire_root();
	makedir(conf.pid_dir, FALSE);
	gchar *name = g_strdup_printf("%s/masqmail.pid", conf.pid_dir);
	if ((fptr = fopen(name, "wt"))) {
		fprintf(fptr, "%d\n", pid);
		fclose(fptr);
		pidfile = name;
		ok = TRUE;
	} else {
		logerrno(LOG_WARNING, "could not write pid file %s", name);
		g_free(name);
	}
	drop_root();
	return ok;
}

/* on -bd or if -q has an argument */
static void
mode_daemon(gboolean do_listen, gint queue_interval)
{
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
		pid_t pid;
		if ((pid = fork()) > 0) {
			write_pidfile(pid);
			exit(0);
		} else if (pid < 0) {
			logerrno(LOG_ERR, "could not fork");
			exit(1);
		}
	} else {
		write_pidfile(getpid());
	}

	signal(SIGTERM, sigterm_handler);

	null_stdio();

	logwrite(LOG_INFO, "%s %s daemon starting\n", PACKAGE, VERSION);
	listen_port(do_listen ? conf.listen_addresses : NULL, queue_interval);
}

/* -bs or called as smtpd or in.smtpd */
static void
mode_smtp(void)
{
	/* accept smtp message on stdin */
	/* write responses to stderr. */

	struct sockaddr_in saddr;
	gchar *peername = NULL;
	socklen_t size = sizeof(saddr);

	DEBUG(5) debugf("accepting smtp message on stdin\n");

	if (getpeername(0, (struct sockaddr *) (&saddr), &size) == 0) {
		if (size >= 2 && saddr.sin_family == AF_INET) {
			peername = g_strdup(inet_ntoa(saddr.sin_addr));
		}
	} else if (errno != ENOTSOCK) {
		logerrno(LOG_ERR, "getpeername() (terminating)");
		exit(1);
	}

	smtp_in(stdin, stdout, peername);

	g_free(peername);
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

	if (return_path) {
		verify_privileged_user("setting return path");
	}

	DEBUG(5) debugf("accepting message on stdin\n");

	msg->received_prot = PROT_LOCAL;

	for (i = 0; i < addr_cnt; i++) {
		address *addr = create_address(addresses[i], A_RFC821, conf.host_name);
		if (!addr) {
			fprintf(stderr, "invalid recipient address '%s': %s\n",
			        addresses[i], parse_error);
			/* should we better ignore this one addr? */
			exit(1);
		}
		msg->rcpt_list = g_list_append(msg->rcpt_list, addr);
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
		fprintf(stderr, "Unknown error (%u)\r\n", err);
		exit(1);
	}

	if (!spool_write(msg, TRUE)) {
		fprintf(stderr, "Could not write spool file\n");
		exit(1);
	}

	/* here the mail is queued and thus in our responsibility */
	logwrite(LOG_INFO, "%s <= <%s> with %s\n", msg->uid,
	         msg->return_path->address, prot_names[PROT_LOCAL]);

	deliver(msg);

	destroy_message(msg);
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

	/* privileged users may delete any mail */
	if (is_privileged_user()) {
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
		fprintf(stderr, "could not find a passwd entry for uid %u: %s\n",
				conf.orig_uid, strerror(errno));
		return FALSE;
	}

	/* non-privileged users may only delete their own messages */
	for (; *id; id++) {
		message *msg = msg_spool_read(*id);
		if (!msg) {
			continue;
		}

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
static void
run_queue(gboolean do_runq_online, char *route_name)
{
	/* queue runs */
	verify_privileged_user("queue run");

	if (!do_runq_online) {
		queue_run();
	} else {
		conf.online_query = g_strdup_printf("/bin/echo %s", route_name);
		queue_run_online();
	}
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

static void
set_mode(enum mta_mode mode)
{
	if (mta_mode && mta_mode!=mode) {
		fprintf(stderr, "operation mode was already specified (%u vs. %u)\n",
		        mta_mode, mode);
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
	gint debug_level = -1;

	ensure_stdio();

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
			const char *cfg = get_optarg(argv, &arg, opt+1);
			if (!cfg) {
				fprintf(stderr, "-C requires filename arg.\n");
				exit(1);
			}
			conf_file = realpath(cfg, NULL);
			if (!conf_file) {
				fprintf(stderr, "specified config file '%s' is invalid.\n", cfg);
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
			gchar *addr = get_optarg(argv, &arg, opt + 1);
			if (!addr) {
				fprintf(stderr, "-f requires address arg.\n");
				exit(1);
			}
			f_address = addr;

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

		} else if (strcmp(opt, "odb") == 0) {
			conf.do_background = TRUE;

		} else if (strcmp(opt, "oi") == 0) {
			opt_i = TRUE;

		} else if (strncmp(opt, "o", 1) == 0) {
			/* ignore all other -oXXX options */

		} else if (strncmp(opt, "qo", 2) == 0) {
			/* must be before the `q' check */
			set_mode(MODE_RUNQUEUE);
			do_runq_online = TRUE;
			route_name = get_optarg(argv, &arg, opt+2);
			if (!route_name) {
				fprintf(stderr, "-qo requires name arg.\n");
				exit(1);
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
			}

		} else if (strcmp(opt, "t") == 0) {
			opt_t = TRUE;

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

	int exe_len = wai_getExecutablePath(NULL, 0, NULL);
	if (exe_len < 0) {
		fprintf(stderr, "cannot determine own executable filepath.\n");
		exit(1);
	}
	char *exe_file = g_malloc(exe_len + 1);
	wai_getExecutablePath(exe_file, exe_len, NULL);
	exe_file[exe_len] = '\0';
	conf.exe_file = exe_file;

	conf.conf_file = conf_file;

	/*
	**  if we are not privileged, and the config file was changed we
	**  implicetely set the the run_as_user flag and give up all
	**  privileges.
	**
	**  So it is possible for a user to run his own daemon without
	**  breaking security.
	*/
	gboolean run_as_user = FALSE;
	if ((strcmp(conf_file, CONF_FILE) != 0) && (conf.orig_uid != 0)) {
		run_as_user = TRUE;
		if (setgid(conf.orig_gid)) {
			logerrno(LOG_ERR, "could not set gid to %u", conf.orig_gid);
			exit(1);
		}
		if (setuid(conf.orig_uid)) {
			logerrno(LOG_ERR, "could not set uid to %u", conf.orig_uid);
			exit(1);
		}
	}

	conf.debug_level = debug_level;  /* for debuggin during read_conf() */
	if (!read_conf()) {
		logwrite(LOG_ERR, "SHUTTING DOWN due to problems reading "
				"config\n");
		exit(5);
	}

	if (do_queue) {
		conf.do_queue = TRUE;
	}
	if (debug_level >= 0) {  /* if >= 0, it was given by argument */
		conf.debug_level = debug_level;
	}

	if (run_as_user) {
		if (!conf.run_as_user) {
			conf.run_as_user = TRUE;
		} else {
			run_as_user = FALSE;
		}
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

	makedir(conf.spool_dir, TRUE);
	makedir(conf.lock_dir, TRUE);
	makedir(conf.log_dir, TRUE);

	if (!conf.run_as_user) {
		// this sets both the effective and the real gid
		if (setgid(conf.mail_gid) != 0) {
			fprintf(stderr, "could not set gid to %u: %s. Is the setuid bit set?\n",
			        conf.mail_gid, strerror(errno));
			exit(1);
		}
		// this sets only the effective uid, as we may need to re-acquire root
		if (seteuid(conf.mail_uid) != 0) {
			fprintf(stderr, "could not set uid to %u: %s. Is the setuid bit set?\n",
			        conf.mail_uid, strerror(errno));
			exit(1);
		}
	}

	logopen();

	DEBUG(1) debugf("----STARTING---- masqmail %s\n", VERSION);

	if (conf.run_as_user) {
		if (!run_as_user) {
			logwrite(LOG_NOTICE, "Changing to run_as_user.\n");
		} else {
			DEBUG(1) debugf("Changing to run_as_user.\n");
		}
	}

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
		return_path = create_address(f_address, A_RFC821, conf.host_name);
		if (!return_path) {
			fprintf(stderr, "invalid return address '%s': %s\n",
			        f_address, parse_error);
			exit(1);
		}
	}

	switch (mta_mode) {
	case MODE_DAEMON:
		mode_daemon(do_listen, queue_interval);
		break;

	case MODE_RUNQUEUE:
		run_queue(do_runq_online, route_name);
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
		fprintf(stderr, "unknown mode: %u\n", mta_mode);
		break;
	}

	logclose();

	exit(0);
}
