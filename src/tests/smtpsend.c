// SPDX-FileCopyrightText: (C) 1999 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "smtp_out.h"

masqmail_conf conf;

extern char *optarg;
extern int optind, opterr, optopt;

void
logwrite(G_GNUC_UNUSED int pri, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(stdout, fmt, args);

	va_end(args);
}

void
logerrno(G_GNUC_UNUSED int pri, const char *fmt, ...)
{
	int saved_errno = errno;
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	va_end(args);
	printf(": %s\n", strerror(saved_errno));
	errno = saved_errno;
}

void
debugf(const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	vfprintf(stdout, fmt, args);

	va_end(args);
}

static gint
smtp_deliver(gchar *host, gint port, GList *resolve_list, message *msg)
{
	DEBUG(5) debugf("smtp_deliver entered\n");

	gchar *err_msg = NULL;
	smtp_base *psb = smtp_out_open(host, port, resolve_list, &err_msg);
	if (!psb) {
		fputs(err_msg, stderr);
		g_free(err_msg);
		return -1;
	}
	set_heloname(psb, msg->return_path->domain, TRUE);
	if (!smtp_out_init(psb, FALSE, &err_msg)) {
		fputs(err_msg, stderr);
		g_free(err_msg);
		goto out;
	}
	smtp_out_msg(psb, msg, msg->return_path, NULL, NULL, &err_msg);
	if (err_msg) {
		fputs(err_msg, stderr);
		g_free(err_msg);
	}
  out:
	smtp_out_quit(psb);
	smtp_error err = psb->error;
	destroy_smtpbase(psb);
	return err;
}

int
main(int argc, char *argv[])
{
	gchar *helo_name = g_malloc(64);
	gchar *server_name = g_strdup("localhost");
	gint server_port = 25;
	GList *resolve_list = g_list_append(NULL, resolve_byname);

	gethostname(helo_name, 63);

	conf.host_name = g_strdup(helo_name);

	while (1) {
		int c;
		c = getopt(argc, argv, "d:p:s:H:");
		if (c == -1)
			break;
		switch (c) {
		case 'd':
			conf.debug_level = atoi(optarg);
			break;
		case 'p':
			server_port = atoi(optarg);
			break;
		case 's':
			g_free(server_name);
			server_name = g_strdup(optarg);
			break;
		case 'H':
			g_free(helo_name);
			helo_name = g_strdup(optarg);
			break;
		default:
			break;
		}
	}

	if (optind < argc) {
		gint ret;
		message *msg = create_message();

		while (optind < argc) {
			msg->rcpt_list = g_list_append(msg->rcpt_list, create_address_qualified(argv[optind++], TRUE, conf.host_name));
		}

		if ((ret = accept_message(stdin, msg, ACC_DOT_IGNORE)) == AERR_OK) {
			if ((ret = smtp_deliver(server_name, server_port, resolve_list, msg)) == smtp_ok) {
				exit(0);
			}
			fprintf(stderr, "deliver failed: %d\n", ret);
			exit(1);
		}
		fprintf(stderr, "accept failed: %d\n", ret);
		exit(1);
	} else {
		fprintf(stderr, "no recipients given.\n");
		exit(3);
	}
}
