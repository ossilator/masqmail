/* pop3_in.c, Copyright (C) 2000 by Oliver Kurth,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/* see RFC 1725 */

#include <sys/wait.h>
#include <sys/stat.h>

#include "masqmail.h"
#include "pop3_in.h"
#include "readsock.h"

#ifdef USE_LIB_CRYPTO
#include <openssl/md5.h>
#else
#include "md5/md5.h"
#endif

#ifdef ENABLE_POP3

/* experimental feature */
#define DO_WRITE_UIDL_EARLY 1

static gchar*
MD5String(char *string)
{
	MD5_CTX context;
	unsigned char digest[16];
	char str_digest[33];
	int i;

#ifdef USE_LIB_CRYPTO
	MD5(string, strlen(string), digest);
#else
	MD5_Init(&context);
	MD5_Update(&context, string, strlen(string));
	MD5_Final(digest, &context);
#endif
	for (i = 0; i < 16; i++)
		sprintf(str_digest + 2 * i, "%02x", digest[i]);

	return g_strdup(str_digest);
}

static pop3_base*
create_pop3base(gint sock, guint flags)
{
	gint dup_sock;

	pop3_base *popb = (pop3_base *) g_malloc(sizeof(pop3_base));
	if (popb) {
		memset(popb, 0, sizeof(pop3_base));

		popb->error = pop3_ok;

		popb->buffer = (gchar *) g_malloc(POP3_BUF_LEN);

		dup_sock = dup(sock);
		popb->out = fdopen(sock, "w");
		popb->in = fdopen(dup_sock, "r");

		popb->flags = flags;
	}
	return popb;
}

static void
pop3_printf(FILE * out, gchar * fmt, ...)
{
	va_list args;
	va_start(args, fmt);

	DEBUG(4) {
		gchar buf[256];
		va_list args_copy;

		va_copy(args_copy, args);
		vsnprintf(buf, 255, fmt, args_copy);
		va_end(args_copy);

		debugf(">>>%s", buf);
	}

	vfprintf(out, fmt, args);
	fflush(out);

	va_end(args);
}

static gboolean
find_uid(pop3_base * popb, gchar * str)
{
	GList *node, *node_next;

	for (node = popb->list_uid_old; node; node = node_next) {
		gchar *uid = (gchar *) (node->data);
		node_next = node->next;
		if (strcmp(uid, str) == 0) {
#if 1
			popb->list_uid_old = g_list_remove_link(popb->list_uid_old, node);
			g_list_free_1(node);
			g_free(uid);
#endif
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean
write_uidl(pop3_base * popb, gchar * user)
{
	gboolean ok = FALSE;
	GList *node;
	gchar *filename = g_strdup_printf("%s/popuidl/%s@%s", conf.spool_dir, user, popb->remote_host);
	gchar *tmpname = g_strdup_printf("%s.tmp", filename);
	FILE *fptr = fopen(tmpname, "wt");

	if (fptr) {
		foreach(popb->drop_list, node) {
			msg_info *info = (msg_info *) (node->data);
			if (info->is_fetched || info->is_in_uidl)
				fprintf(fptr, "%s\n", info->uid);
		}
		fclose(fptr);
		ok = (rename(tmpname, filename) != -1);
	}

	g_free(tmpname);
	g_free(filename);
	return ok;
}

static gboolean
read_uidl_fname(pop3_base * popb, gchar * filename)
{
	gboolean ok = FALSE;
	FILE *fptr = fopen(filename, "rt");
	gchar buf[256];

	if (fptr) {
		popb->list_uid_old = NULL;
		while (fgets(buf, 255, fptr)) {
			if (buf[strlen(buf) - 1] == '\n') {
				g_strchomp(buf);
				popb->list_uid_old = g_list_append(popb->list_uid_old, g_strdup(buf));
			} else {
				logwrite(LOG_ALERT, "broken uid: %s\n", buf);
				break;
			}
		}
		fclose(fptr);
		ok = TRUE;
	} else
		logwrite(LOG_ALERT, "opening of %s failed: %s", filename, strerror(errno));
	return ok;
}

static gboolean
read_uidl(pop3_base * popb, gchar * user)
{
	gboolean ok = FALSE;
	struct stat statbuf;
	gchar *filename = g_strdup_printf("%s/popuidl/%s@%s", conf.spool_dir, user, popb->remote_host);

	if (stat(filename, &statbuf) == 0) {
		ok = read_uidl_fname(popb, filename);
		if (ok) {
			GList *drop_node;
			foreach(popb->drop_list, drop_node) {
				msg_info *info = (msg_info *) (drop_node->data);
				if (find_uid(popb, info->uid)) {
					DEBUG(5) debugf("msg with uid '%s' already known\n", info->uid);
					info->is_in_uidl = TRUE;
					popb->uidl_known_cnt++;
				} else
					DEBUG(5) debugf("msg with uid '%s' not known\n", info->uid);
			}
		}
	} else {
		logwrite(LOG_DEBUG, "no uidl file '%s' found\n", filename);
		ok = TRUE;
	}

	g_free(filename);
	return ok;  /* return code is irrelevant, do not check... */
}

static gboolean
read_response(pop3_base * popb, int timeout)
{
	gint len;

	len = read_sockline(popb->in, popb->buffer, POP3_BUF_LEN, timeout, READSOCKL_CHUG);

	if (len == -3) {
		popb->error = pop3_timeout;
		return FALSE;
	} else if (len == -2) {
		popb->error = pop3_syntax;
		return FALSE;
	} else if (len == -1) {
		popb->error = pop3_eof;
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_response(pop3_base * popb)
{
	char c = popb->buffer[0];

	if (c == '+') {
		popb->error = pop3_ok;
		return TRUE;
	} else if (c == '-')
		popb->error = pop3_fail;
	else
		popb->error = pop3_syntax;
	return FALSE;
}

static gboolean
strtoi(gchar * p, gchar ** pend, gint * val)
{
	gchar buf[12];
	gint i = 0;

	while (*p && isspace(*p))
		p++;
	if (*p) {
		while ((i < 11) && isdigit(*p))
			buf[i++] = *(p++);
		buf[i] = 0;
		*val = atoi(buf);
		*pend = p;
		return TRUE;
	}
	return FALSE;
}

static gboolean
check_response_int_int(pop3_base * popb, gint * arg0, gint * arg1)
{
	if (check_response(popb)) {
		gchar *p = &(popb->buffer[3]);
		gchar *pe;

		if (strtoi(p, &pe, arg0)) {
			DEBUG(5) debugf("arg0 = %d\n", *arg0);
			p = pe;
			if (strtoi(p, &pe, arg1))
				DEBUG(5) debugf("arg1 = %d\n", *arg1);
			return TRUE;
			/* FIXME: Paolo's code has the return stmt
			   inside the if block right above it. What
			   is correct? */
		}
		popb->error = pop3_syntax;
	}
	return FALSE;
}

static gboolean
get_drop_listing(pop3_base * popb)
{
	gchar buf[64];

	DEBUG(5) debugf("get_drop_listing() entered\n");

	while (1) {
		gint len = read_sockline(popb->in, buf, 64, POP3_CMD_TIMEOUT, READSOCKL_CHUG);
		if (len > 0) {
			if (buf[0] == '.')
				return TRUE;
			else {
				gint number, msg_size;
				gchar *p = buf, *pe;
				if (strtoi(p, &pe, &number)) {
					p = pe;
					if (strtoi(p, &pe, &msg_size)) {
						msg_info *info = g_malloc(sizeof(msg_info));
						info->number = number;
						info->size = msg_size;

						DEBUG(5) debugf ("get_drop_listing(), number = %d, msg_size = %d\n", number, msg_size);

						info->uid = NULL;
						info->is_fetched = FALSE;
						info->is_in_uidl = FALSE;
						popb->drop_list = g_list_append(popb->drop_list, info);
					} else {
						popb->error = pop3_syntax;
						break;
					}
				} else {
					popb->error = pop3_syntax;
					break;
				}
			}
		} else {
			popb->error = (len == -1) ? pop3_eof : pop3_timeout;
			return FALSE;
		}
	}
	return FALSE;
}

static gboolean
get_uid_listing(pop3_base * popb)
{
	gchar buf[64];

	while (1) {
		gint len = read_sockline(popb->in, buf, 64, POP3_CMD_TIMEOUT, READSOCKL_CHUG);
		if (len > 0) {
			if (buf[0] == '.')
				return TRUE;
			else {
				gint number;
				gchar *p = buf, *pe;
				if (strtoi(p, &pe, &number)) {
					msg_info *info = NULL;
					GList *drop_node;

					p = pe;
					while (*p && isspace(*p))
						p++;

					foreach(popb->drop_list, drop_node) {
						msg_info *curr_info = (msg_info *) (drop_node->data);
						if (curr_info->number == number) {
							info = curr_info;
							break;
						}
					}
					if (info) {
						info->uid = g_strdup(p);
						g_strchomp(info->uid);
					}

				} else {
					popb->error = pop3_syntax;
					break;
				}
			}
		}
	}
	return FALSE;
}

static gboolean
check_init_response(pop3_base * popb)
{
	if (check_response(popb)) {
		gchar buf[256];
		gchar *p = popb->buffer;
		gint i = 0;
		if (*p) {
			while (*p && (*p != '<'))
				p++;
			while (*p && (*p != '>') && (i < 254))
				buf[i++] = *(p++);
			buf[i++] = '>';
			buf[i] = '\0';

			popb->timestamp = g_strdup(buf);

			return TRUE;
		}
	}
	return FALSE;
}

void
pop3_in_close(pop3_base * popb)
{
	GList *node;

	fclose(popb->in);
	fclose(popb->out);

	close(popb->sock);

	foreach(popb->list_uid_old, node) {
		gchar *uid = (gchar *) (node->data);
		g_free(uid);
	}
	g_list_free(popb->list_uid_old);

	foreach(popb->drop_list, node) {
		msg_info *info = (msg_info *) (node->data);
		if (info->uid)
			g_free(info->uid);
		g_free(info);
	}
	g_list_free(popb->drop_list);

	if (popb->buffer)
		g_free(popb->buffer);
	if (popb->timestamp)
		g_free(popb->timestamp);
}

pop3_base*
pop3_in_open(gchar * host, gint port, GList * resolve_list, guint flags)
{
	pop3_base *popb;
	gint sock;
	mxip_addr *addr;

	DEBUG(5) debugf("pop3_in_open entered, host = %s\n", host);

	if ((addr = connect_resolvelist(&sock, host, port, resolve_list))) {
		/* create structure to hold status data: */
		popb = create_pop3base(sock, flags);
		popb->remote_host = addr->name;

		DEBUG(5) {
			struct sockaddr_in name;
			int len;
			getsockname(sock, (struct sockaddr *) (&name), &len);
			debugf("socket: name.sin_addr = %s\n", inet_ntoa(name.sin_addr));
		}
		return popb;
	}
	return NULL;
}

pop3_base*
pop3_in_open_child(gchar * cmd, guint flags)
{
	pop3_base *popb;
	gint sock;

	DEBUG(5) debugf("pop3_in_open_child entered, cmd = %s\n", cmd);
	sock = child(cmd);
	if (sock > 0) {
		popb = create_pop3base(sock, flags);
		popb->remote_host = NULL;
		return popb;
	}
	logwrite(LOG_ALERT, "child failed (sock = %d): %s\n", sock, strerror(errno));

	return NULL;
}

gboolean
pop3_in_init(pop3_base * popb)
{
	gboolean ok;

	if ((ok = read_response(popb, POP3_INITIAL_TIMEOUT))) {
		ok = check_init_response(popb);
	}
	if (!ok)
		/* pop3_in_log_failure(popb, NULL); */
		logwrite(LOG_ALERT, "pop3 failed\n");
	return ok;
}

gboolean
pop3_in_login(pop3_base * popb, gchar * user, gchar * pass)
{
	if (popb->flags & POP3_FLAG_APOP) {

		gchar *string = g_strdup_printf("%s%s", popb->timestamp, pass);
		gchar *digest = MD5String(string);
		pop3_printf(popb->out, "APOP %s %s\r\n", user, digest);
		g_free(string);
		g_free(digest);
		if (read_response(popb, POP3_CMD_TIMEOUT)) {
			if (check_response(popb))
				return TRUE;
			else
				popb->error = pop3_login_failure;
		}

	} else {

		pop3_printf(popb->out, "USER %s\r\n", user);
		if (read_response(popb, POP3_CMD_TIMEOUT)) {
			if (check_response(popb)) {
				pop3_printf(popb->out, "PASS %s\r\n", pass);
				if (read_response(popb, POP3_CMD_TIMEOUT)) {
					if (check_response(popb))
						return TRUE;
					else
						popb->error = pop3_login_failure;
				}
			} else {
				popb->error = pop3_login_failure;
			}
		}
	}
	return FALSE;
}

gboolean
pop3_in_stat(pop3_base * popb)
{
	pop3_printf(popb->out, "STAT\r\n");
	if (read_response(popb, POP3_CMD_TIMEOUT)) {
		gint msg_cnt, mbox_size;
		if (check_response_int_int(popb, &msg_cnt, &mbox_size)) {
			popb->msg_cnt = msg_cnt;
			popb->mbox_size = mbox_size;

			return TRUE;
		}
	}
	return FALSE;
}

gboolean
pop3_in_list(pop3_base * popb)
{
	pop3_printf(popb->out, "LIST\r\n");
	if (read_response(popb, POP3_CMD_TIMEOUT)) {
		if (get_drop_listing(popb)) {
			return TRUE;
		}
	}
	return FALSE;
}

gboolean
pop3_in_dele(pop3_base * popb, gint number)
{
	pop3_printf(popb->out, "DELE %d\r\n", number);
	if (read_response(popb, POP3_CMD_TIMEOUT)) {
		return TRUE;
	}
	return FALSE;
}

message*
pop3_in_retr(pop3_base * popb, gint number, address * rcpt)
{
	accept_error err;

	pop3_printf(popb->out, "RETR %d\r\n", number);
	if (read_response(popb, POP3_CMD_TIMEOUT)) {
		message *msg = create_message();
		msg->received_host = popb->remote_host;
		msg->received_prot = (popb->flags & POP3_FLAG_APOP) ? PROT_APOP : PROT_POP3;
		msg->transfer_id = (popb->next_id)++;
		msg->rcpt_list = g_list_append(NULL, copy_address(rcpt));

		if ((err = accept_message(popb->in, msg, ACC_MAIL_FROM_HEAD
		                          | (conf.do_save_envelope_to ? ACC_SAVE_ENVELOPE_TO : 0)))
		    == AERR_OK)
			return msg;

		destroy_message(msg);
	}
	return NULL;
}

gboolean
pop3_in_uidl(pop3_base * popb)
{
	pop3_printf(popb->out, "UIDL\r\n");
	if (read_response(popb, POP3_CMD_TIMEOUT)) {
		if (get_uid_listing(popb)) {
			return TRUE;
		}
	}
	return FALSE;
}

gboolean
pop3_in_quit(pop3_base * popb)
{
	pop3_printf(popb->out, "QUIT\r\n");
	DEBUG(4) debugf("QUIT\n");
	signal(SIGALRM, SIG_DFL);
	return TRUE;
}

/* Send a DELE command for each message in (the old) uid listing.
   This is to prevent mail from to be kept on server, if a previous
   transaction was interupted. */
gboolean
pop3_in_uidl_dele(pop3_base * popb)
{
	GList *drop_node;

	foreach(popb->drop_list, drop_node) {
		msg_info *info = (msg_info *) (drop_node->data);
		/* if(find_uid(popb, info->uid)){ */
		if (info->is_in_uidl) {
			if (!pop3_in_dele(popb, info->number))
				return FALSE;
			/* TODO: it probably makes sense to also delete this uid from the listing */
		}
	}
	return TRUE;
}

gboolean
pop3_get(pop3_base * popb, gchar * user, gchar * pass, address * rcpt, address * return_path,
         gint max_count, gint max_size, gboolean max_size_delete)
{
	gboolean ok = FALSE;
	gint num_children = 0;

	DEBUG(5) debugf("rcpt = %s@%s\n", rcpt->local_part, rcpt->domain);

	signal(SIGCHLD, SIG_DFL);

	if (pop3_in_init(popb)) {
		if (pop3_in_login(popb, user, pass)) {
			if (pop3_in_stat(popb)) {
				if (popb->msg_cnt > 0) {

					logwrite(LOG_NOTICE | LOG_VERBOSE, "%d message(s) for user %s at %s\n",
					         popb->msg_cnt, user, popb->remote_host);

					if (pop3_in_list(popb)) {
						gboolean do_get = !(popb->flags & POP3_FLAG_UIDL);
						if (!do_get)
							do_get = pop3_in_uidl(popb);
						if (do_get) {
							gint count = 0;
							GList *drop_node;

							if (popb->flags & POP3_FLAG_UIDL) {
								read_uidl(popb, user);
								logwrite(LOG_VERBOSE | LOG_NOTICE, "%d message(s) already in uidl.\n", popb->uidl_known_cnt);
							}
							if ((popb->flags & POP3_FLAG_UIDL) && (popb->flags & POP3_FLAG_UIDL_DELE))
								pop3_in_uidl_dele(popb);

							foreach(popb->drop_list, drop_node) {

								msg_info *info = (msg_info *) (drop_node->data);
								gboolean do_get_this = !(popb->flags & POP3_FLAG_UIDL);
								/* if(!do_get_this) do_get_this = !find_uid(popb, info->uid); */
								if (!do_get_this)
									do_get_this = !(info->is_in_uidl);
								if (do_get_this) {

									if ((info->size < max_size) || (max_size == 0)) {
										message *msg;

										logwrite(LOG_VERBOSE | LOG_NOTICE, "receiving message %d\n", info->number);
										msg = pop3_in_retr(popb, info->number, rcpt);

										if (msg) {
											if (return_path)
												msg->return_path = copy_address(return_path);
											if (spool_write(msg, TRUE)) {
												pid_t pid;
												logwrite(LOG_NOTICE, "%s <= %s host=%s with %s\n", msg->uid,
												         addr_string(msg->return_path), popb->remote_host,
												         (popb->flags & POP3_FLAG_APOP) ? prot_names [PROT_APOP] : prot_names [PROT_POP3]);
												info->is_fetched = TRUE;
												count++;
#if DO_WRITE_UIDL_EARLY
												if (popb->flags & POP3_FLAG_UIDL)
													write_uidl(popb, user);
#endif
												if (!conf.do_queue) {

													/* wait for child processes. If there are too many, we wait blocking, before we fork another one */
													while (num_children > 0) {
														int status, options = WNOHANG;
														pid_t pid;

														if (num_children >= POP3_MAX_CHILDREN) {
															logwrite(LOG_NOTICE, "too many children - waiting\n");
															options = 0;
														}
														if ((pid = waitpid(0, &status, options)) > 0) {
															num_children--;
															if (WEXITSTATUS(status) != EXIT_SUCCESS)
																logwrite(LOG_WARNING, "delivery process with pid %d returned %d\n", pid, WEXITSTATUS (status));
															if (WIFSIGNALED(status))
																logwrite(LOG_WARNING, "delivery process with pid %d got signal: %d\n", pid, WTERMSIG (status));
														} else if (pid < 0) {
															logwrite(LOG_WARNING, "wait got error: %s\n", strerror(errno));
														}
													}

													if ((pid = fork()) == 0) {
														deliver(msg);
														_exit(EXIT_SUCCESS);
													} else if (pid < 0) {
														logwrite(LOG_ALERT | LOG_VERBOSE, "could not fork for delivery, id = %s: %s\n", msg->uid, strerror(errno));
													} else
														num_children++;
												} else {
													DEBUG(1) debugf("queuing forced by configuration or option.\n");
												}
												if (popb->flags & POP3_FLAG_DELETE)
													pop3_in_dele(popb, info->number);

												destroy_message(msg);
											}	/* if(spool_write(msg, TRUE)) */
										} else {
											logwrite(LOG_ALERT, "retrieving of message %d failed: %d\n", info->number, popb->error);
										}
									} else {
										/* info->size > max_size */
										logwrite(LOG_NOTICE | LOG_VERBOSE, "size of message #%d (%d) > max_size (%d)\n", info->number, info->size, max_size);
										if (max_size_delete)
											if (popb->flags & POP3_FLAG_DELETE)
												pop3_in_dele(popb, info->number);
									}
								} /* if(do_get_this) ... */
								else {
									if (popb->flags & POP3_FLAG_UIDL) {
										info->is_fetched = TRUE;  /* obsolete? */
										logwrite(LOG_VERBOSE, "message %d already known\n", info->number);
										DEBUG(1) debugf("message %d (uid = %s) not fetched\n", info->number, info->uid);
#if 0
#if DO_WRITE_UIDL_EARLY
										write_uidl(popb, user);  /* obsolete? */
#endif
#endif
									}
								}
								if ((max_count != 0) && (count >= max_count))
									break;
							}	/* foreach() */
#if DO_WRITE_UIDL_EARLY
#else
							if (popb->flags & POP3_FLAG_UIDL)
								write_uidl(popb, user);
#endif
						}  /* if(pop3_in_uidl(popb) ... */
					}  /* if(pop3_in_list(popb)) */
				}  /* if(popb->msg_cnt > 0) */
				else {
					logwrite(LOG_NOTICE | LOG_VERBOSE, "no messages for user %s at %s\n", user, popb->remote_host);
				}
				ok = TRUE;
			}
			pop3_in_quit(popb);
		} else {
			logwrite(LOG_ALERT | LOG_VERBOSE, "pop3 login failed for user %s, host = %s\n", user, popb->remote_host);
		}
	}
	if (!ok) {
		logwrite(LOG_ALERT | LOG_VERBOSE, "pop3 failed, error = %d\n", popb->error);
	}

	while (num_children > 0) {
		int status;
		pid_t pid;
		if ((pid = wait(&status)) > 0) {
			num_children--;
			if (WEXITSTATUS(status) != EXIT_SUCCESS)
				logwrite(LOG_WARNING, "delivery process with pid %d returned %d\n", pid, WEXITSTATUS(status));
			if (WIFSIGNALED(status))
				logwrite(LOG_WARNING, "delivery process with pid %d got signal: %d\n", pid, WTERMSIG(status));
		} else {
			logwrite(LOG_WARNING, "wait got error: %s\n", strerror(errno));
		}
	}

	return ok;
}

/* function just to log into a pop server,
   for pop_before_smtp (or is it smtp_after_pop?)
*/

gboolean
pop3_login(gchar * host, gint port, GList * resolve_list, gchar * user, gchar * pass, guint flags)
{
	gboolean ok = FALSE;
	pop3_base *popb;

	signal(SIGCHLD, SIG_IGN);

	if ((popb = pop3_in_open(host, port, resolve_list, flags))) {
		if (pop3_in_init(popb)) {
			if (pop3_in_login(popb, user, pass))
				ok = TRUE;
			else
				logwrite(LOG_ALERT | LOG_VERBOSE, "pop3 login failed for user %s, host = %s\n", user, host);
		}
		pop3_in_close(popb);
	}
	return ok;
}

#endif
