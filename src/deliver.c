/*  MasqMail
    Copyright (C) 1999-2002 Oliver Kurth

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

#include <fnmatch.h>
#include <sysexits.h>
#include <netdb.h>

#include "masqmail.h"
#include "smtp_out.h"

/* collect failed/defered rcpts for failure/warning messages */
/* returns TRUE if either there are no failures or a failure message has been successfully sent */
gboolean
delivery_failures(message * msg, GList * rcpt_list, gchar * err_fmt, ...)
{
	gboolean ok_fail = TRUE, ok_warn = TRUE;
	time_t now = time(NULL);

	GList *failed_list = NULL, *defered_list = NULL, *rcpt_node;
	va_list args;
	va_start(args, err_fmt);

	foreach(rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);

		if (addr_is_defered(rcpt)) {
			if ((now - msg->received_time) >= conf.max_defer_time) {
				addr_mark_failed(rcpt);
			} else
				defered_list = g_list_prepend(defered_list, rcpt);
		}
		if (addr_is_failed(rcpt))
			failed_list = g_list_prepend(failed_list, rcpt);
	}
	if (failed_list != NULL) {
		ok_fail = fail_msg(msg, conf.errmsg_file, failed_list, err_fmt, args);
		g_list_free(failed_list);
	}
	if (defered_list != NULL) {
		ok_warn = warn_msg(msg, conf.warnmsg_file, defered_list, err_fmt, args);
		g_list_free(defered_list);
	}
	va_end(args);
	return ok_fail && ok_warn;
}

static gint
_g_list_strcasecmp(gconstpointer a, gconstpointer b)
{
	return (gint) strcasecmp(a, b);
}

gboolean
deliver_local(msg_out * msgout)
{
	message *msg = msgout->msg;
	GList *rcpt_list = msgout->rcpt_list;
	GList *rcpt_node;
	gboolean ok = TRUE, flag = FALSE, ok_fail = FALSE;

	DEBUG(5) debugf("deliver_local entered\n");

	flag = (msg->data_list == NULL);
	if (flag) {
		if (!(ok = spool_read_data(msg))) {
			logwrite(LOG_ALERT, "could not open data spool file for %s\n", msg->uid);
		}
	}
	if (!ok)
		return FALSE;

	ok = FALSE;
	for (rcpt_node = g_list_first(rcpt_list); rcpt_node; rcpt_node = g_list_next(rcpt_node)) {
		GList *hdr_list;
		address *rcpt = (address *) (rcpt_node->data);
		address *env_addr = addr_find_ancestor(rcpt);
		address *ret_path = msg->return_path;
		header *retpath_hdr, *envto_hdr;

		/* we need a private copy of the hdr list because we add headers here that belong to the rcpt only.
		   g_list_copy copies only the nodes, so it is safe to g_list_free it */
		hdr_list = g_list_copy(msg->hdr_list);
		retpath_hdr = create_header(HEAD_ENVELOPE_TO, "Envelope-to: %s\n", addr_string(env_addr));
		envto_hdr = create_header(HEAD_RETURN_PATH, "Return-path: %s\n", addr_string(ret_path));

		hdr_list = g_list_prepend(hdr_list, envto_hdr);
		hdr_list = g_list_prepend(hdr_list, retpath_hdr);

		if (rcpt->local_part[0] == '|') {
			DEBUG(1) debugf("attempting to deliver %s with pipe\n", msg->uid);
			if (pipe_out(msg, hdr_list, rcpt, &(rcpt->local_part[1]),
			    (conf.pipe_fromline ? MSGSTR_FROMLINE : 0)
			    | (conf.pipe_fromhack ? MSGSTR_FROMHACK : 0))) {
				logwrite(LOG_NOTICE, "%s => %s <%s@%s> with pipe\n",
				         msg->uid, rcpt->local_part, env_addr->local_part, env_addr->domain);
				addr_mark_delivered(rcpt);
				ok = TRUE;
			} else {
				if ((errno != (1024 + EX_TEMPFAIL)) && (errno != EAGAIN)) {
					addr_mark_failed(rcpt);
				} else {
					addr_mark_defered(rcpt);  /* has no effect yet, except that mail remains in spool */
				}
			}
		} else {
			/* figure out which mailbox type should be used for this user */
			gchar *user = rcpt->local_part;
			gchar *mbox_type = conf.mbox_default;

			if (g_list_find_custom (conf.mbox_users, user, _g_list_strcasecmp) != NULL)
				mbox_type = "mbox";
			else if (g_list_find_custom (conf.mda_users, user, _g_list_strcasecmp) != NULL)
				mbox_type = "mda";
			else if (g_list_find_custom (conf.maildir_users, user, _g_list_strcasecmp) != NULL)
				mbox_type = "maildir";

			if (strcmp(mbox_type, "mbox") == 0) {
				DEBUG(1) debugf("attempting to deliver %s with mbox\n", msg->uid);
				if (append_file(msg, hdr_list, rcpt->local_part)) {
					if (env_addr != rcpt) {
						logwrite(LOG_NOTICE, "%s => %s@%s <%s@%s> with mbox\n",
						         msg->uid, rcpt->local_part, rcpt->domain,
						         env_addr->local_part, env_addr->domain);
					} else {
						logwrite(LOG_NOTICE, "%s => <%s@%s> with mbox\n",
						         msg->uid, rcpt->local_part, rcpt->domain);
					}
					addr_mark_delivered(rcpt);
					ok = TRUE;
				} else {
					if (errno != EAGAIN) {  /* prevents 'Resource temporarily unavailable (11)' */
						addr_mark_failed(rcpt);
					} else {
						addr_mark_defered(rcpt);
					}
				}

			} else if (strcmp(mbox_type, "mda") == 0) {
				if (conf.mda) {
					gchar *cmd = g_malloc(256);
					GList *var_table = var_table_rcpt(var_table_msg(NULL, msg), rcpt);

					DEBUG(1) debugf("attempting to deliver %s with mda\n", msg->uid);

					if (expand(var_table, conf.mda, cmd, 256)) {

						if (pipe_out(msg, hdr_list, rcpt, cmd, (conf.mda_fromline ? MSGSTR_FROMLINE : 0)
						    | (conf.mda_fromhack ? MSGSTR_FROMHACK : 0))) {
							logwrite(LOG_NOTICE, "%s => %s@%s with mda (cmd = '%s')\n",
							         msg->uid, rcpt->local_part, rcpt->domain, cmd);
							addr_mark_delivered(rcpt);
							ok = TRUE;
						} else {
							if ((errno != (1024 + EX_TEMPFAIL)) && (errno != EAGAIN)) {
								addr_mark_failed(rcpt);
							} else {
								addr_mark_defered(rcpt);  /* has no effect yet, except that mail remains in spool */
							}
						}
					} else
						logwrite(LOG_ALERT, "could not expand string %s\n", conf.mda);

					destroy_table(var_table);
				} else
					logwrite(LOG_ALERT, "mbox type is mda, but no mda command given in configuration\n");

#ifdef ENABLE_MAILDIR
			} else if (strcmp(mbox_type, "maildir") == 0) {
				DEBUG(1) debugf("attempting to deliver %s with maildir\n", msg->uid);
				if (maildir_out(msg, hdr_list, rcpt->local_part, 0)) {
					if (env_addr != rcpt) {
						logwrite(LOG_NOTICE, "%s => %s@%s <%s@%s> with local\n", msg->uid,
						         rcpt->local_part, rcpt->domain, env_addr->local_part, env_addr->domain);
					} else {
						logwrite(LOG_NOTICE, "%s => <%s@%s> with maildir\n", msg->uid,
						         rcpt->local_part, rcpt->domain);
					}
					addr_mark_delivered(rcpt);
					ok = TRUE;
				} else
					addr_mark_failed(rcpt);
#endif
			} else
				logwrite(LOG_ALERT, "unknown mbox type '%s'\n", mbox_type);
		}

		destroy_header(retpath_hdr);
		destroy_header(envto_hdr);

		g_list_free(hdr_list);
	}
	ok_fail = delivery_failures(msg, rcpt_list, "%s (%d)", ext_strerror(errno), errno);

	if (flag)
		msg_free_data(msg);
	if (ok || ok_fail)
		deliver_finish(msgout);

	return ok;
}

/* make a list of rcpt's of a message that are local return a new copy of the list */
void
msg_rcptlist_local(GList * rcpt_list, GList ** p_local_list, GList ** p_nonlocal_list)
{
	GList *rcpt_node;

	foreach(rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);
		GList *dom_node;

		DEBUG(5) debugf("checking address %s\n", rcpt->address);

		/* search for local host list: */
		foreach(conf.local_hosts, dom_node) {
			if (strcasecmp(dom_node->data, rcpt->domain) == 0) {
				*p_local_list = g_list_append(*p_local_list, rcpt);
				DEBUG(5) debugf("<%s@%s> is local\n", rcpt->local_part, rcpt->domain);
				break;
			} else {
				*p_nonlocal_list = g_list_append(*p_nonlocal_list, rcpt);
			}
		}
	}
}

gboolean
deliver_msglist_host_pipe(connect_route * route, GList * msgout_list, gchar * host, GList * res_list)
{
	gboolean ok = TRUE;
	GList *msgout_node;

	DEBUG(5) debugf("deliver_msglist_host_pipe entered\n");

	if (route->pipe == NULL) {
		logwrite(LOG_ALERT, "no pipe command given for route (protocol is pipe!)\n");
		return FALSE;
	}

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		gboolean flag, ok_msg = TRUE, ok_fail = FALSE;
		message *msg = msgout->msg;
		GList *rcpt_node, *rcpt_list = msgout->rcpt_list;

		DEBUG(1) debugf("attempting to deliver %s with pipe\n", msg->uid);

		flag = (msg->data_list == NULL);
		if (flag) {
			if (!(ok_msg = spool_read_data(msg))) {
				logwrite(LOG_ALERT, "could not open data spool file for %s\n", msg->uid);
			}
		}
		if (!ok_msg)
			continue;

		ok = FALSE;
		foreach(rcpt_list, rcpt_node) {
			address *rcpt = (address *) (rcpt_node->data);
			gchar *cmd = g_malloc(256);
			GList *var_table = var_table_rcpt(var_table_msg(NULL, msg), rcpt);

			DEBUG(1) debugf("attempting to deliver %s to %s@%s with pipe\n", msg->uid, rcpt->local_part, rcpt->domain);

			if (expand(var_table, route->pipe, cmd, 256)) {

				if (pipe_out(msg, msg->hdr_list, rcpt, cmd, (route->pipe_fromline ? MSGSTR_FROMLINE : 0)
				    | (route->pipe_fromhack ? MSGSTR_FROMHACK : 0))) {
					logwrite(LOG_NOTICE, "%s => %s@%s with pipe (cmd = '%s')\n",
					         msg->uid, rcpt->local_part, rcpt->domain, cmd);
					addr_mark_delivered(rcpt);
					ok = TRUE;
				} else {
					logwrite(LOG_ALERT, "pipe_out '%s' failed\n", route->pipe);

					if (route->connect_error_fail) {
						addr_mark_failed(rcpt);
					} else {
						addr_mark_defered(rcpt);
					}
				}
			} else
				logwrite(LOG_ALERT, "could not expand string %s\n", route->pipe);

			destroy_table(var_table);
		}
		ok_fail = delivery_failures(msg, rcpt_list, "%s", strerror(errno));

		if (flag)
			msg_free_data(msg);

		if (ok || ok_fail)
			deliver_finish(msgout);
	}

	return ok;
}

/* deliver list of messages to one host and finishes them if the message was delivered to at least one rcpt.
   Returns TRUE if at least one msg was delivered to at least one rcpt.
*/
gboolean
deliver_msglist_host_smtp(connect_route * route, GList * msgout_list, gchar * host, GList * res_list)
{
	gboolean ok = FALSE;
	GList *msgout_node;
	smtp_base *psb;
	gint port;

	/* paranoid check: */
	if (msgout_list == NULL) {
		logwrite(LOG_ALERT, "Ooops: empty list of messages in deliver_msglist_host()\n");
		return FALSE;
	}

	if (host == NULL) {
		host = route->mail_host->address;
		port = route->mail_host->port;
	} else
		port = conf.remote_port;

#ifdef ENABLE_POP3
	if (route->pop3_login) {
		if (!(pop_before_smtp(route->pop3_login)))
			return FALSE;
	}
#endif

	if ((psb = (route->wrapper ? smtp_out_open_child(route->wrapper) : smtp_out_open(host, port, res_list)))) {

		if (route->wrapper)
			psb->remote_host = host;

		set_heloname(psb, route->helo_name ? route->helo_name : conf.host_name, route->do_correct_helo);

#ifdef ENABLE_AUTH
		if ((route->auth_name) && (route->auth_login) && (route->auth_secret))
			set_auth(psb, route->auth_name, route->auth_login, route->auth_secret);
#endif
		if (smtp_out_init(psb)) {

			if (!route->do_pipelining)
				psb->use_pipelining = FALSE;

			foreach(msgout_list, msgout_node) {
				msg_out *msgout = (msg_out *) (msgout_node->data);
				gboolean flag, ok_msg = FALSE, ok_fail = FALSE;
				message *msg = msgout->msg;

				/* we may have to read the data at this point and remember if we did */
				flag = (msg->data_list == NULL);
				if (flag) {
					if (!spool_read_data(msg)) {
						logwrite(LOG_ALERT, "could not open data spool file %s\n", msg->uid);
						break;
					}
				}

				smtp_out_msg(psb, msg, msgout->return_path, msgout->rcpt_list, msgout->hdr_list);

				ok_fail = delivery_failures(msg, msgout->rcpt_list,
				                            "while connected with %s, the server replied\n\t%s", host, psb->buffer);

				if ((psb->error == smtp_eof)
				    || (psb->error == smtp_timeout)) {
					/* connection lost */
					break;
				} else if (psb->error != smtp_ok) {
					if (g_list_next(msgout_node) != NULL)
						if (!smtp_out_rset(psb))
							break;
				}
				ok_msg = (psb->error == smtp_ok);

				if (flag)
					msg_free_data(msg);
				if (ok_msg)
					ok = TRUE;
				if (ok_msg || ok_fail) {
					deliver_finish(msgout);
				}
			}
			if (psb->error == smtp_ok || (psb->error == smtp_fail)
			    || (psb->error == smtp_trylater) || (psb->error == smtp_syntax)) {
				smtp_out_quit(psb);
			}
		} else {
			/* smtp_out_init() failed */
			if ((psb->error == smtp_fail) || (psb->error == smtp_trylater) || (psb->error == smtp_syntax)) {
				smtp_out_quit(psb);

				foreach(msgout_list, msgout_node) {
					msg_out *msgout = (msg_out *) (msgout_node->data);
					smtp_out_mark_rcpts(psb, msgout->rcpt_list);

					if (delivery_failures(msgout->msg, msgout->rcpt_list,
					    "while connected with %s, the server replied\n\t%s", host, psb->buffer))
						deliver_finish(msgout);
				}
			}
		}
		destroy_smtpbase(psb);
	} else {
		/* smtp_out_open() failed */
		foreach(msgout_list, msgout_node) {
			msg_out *msgout = (msg_out *) (msgout_node->data);
			GList *rcpt_node;

			for (rcpt_node = g_list_first(msgout->rcpt_list); rcpt_node; rcpt_node = g_list_next(rcpt_node)) {
				address *rcpt = (address *) (rcpt_node->data);

				addr_unmark_delivered(rcpt);
				if (route->connect_error_fail) {
					addr_mark_failed(rcpt);
				} else {
					addr_mark_defered(rcpt);
				}
				if (route->wrapper
				    ? delivery_failures(msgout->msg, msgout->rcpt_list, "could not open wrapper:\n\t%s",
				                        strerror(errno))
				    : delivery_failures(msgout->msg, msgout->rcpt_list, "could not open connection to %s:%d :\n\t%s",
				                        host, port, h_errno != 0 ? hstrerror(h_errno) : strerror(errno)))
					deliver_finish(msgout);
			}
		}
	}
	return ok;
}

gboolean
deliver_msglist_host(connect_route * route, GList * msgout_list, gchar * host, GList * res_list)
{
	DEBUG(5) debugf("protocol = %s\n", route->protocol);

	if (strcmp(route->protocol, "pipe") == 0) {
		return deliver_msglist_host_pipe(route, msgout_list, host, res_list);
	} else {
		return deliver_msglist_host_smtp(route, msgout_list, host, res_list);
	}
}

/*
  delivers messages in msgout_list using route
*/
gboolean
deliver_route_msgout_list(connect_route * route, GList * msgout_list)
{
	gboolean ok = FALSE;

	DEBUG(5) debugf("deliver_route_msgout_list entered, route->name = %s\n", route->name);

	if (route->mail_host != NULL) {
		/* this is easy... */
		if (deliver_msglist_host(route, msgout_list, NULL, route->resolve_list))
			ok = TRUE;

	} else {
		/* this is not easy... */
		GList *mo_ph_list;

		mo_ph_list = route_msgout_list(route, msgout_list);
		/* okay, now we have ordered our messages by the hosts. */
		if (mo_ph_list != NULL) {
			GList *mo_ph_node;
			/* TODO: It would be nice to be able to fork for each host.
			   We cannot do that yet because of complications with finishing the
			   messages. Threads could be a solution because they use the same
			   memory. But we are not thread safe yet...
			 */
			foreach(mo_ph_list, mo_ph_node) {
				msgout_perhost *mo_ph = (msgout_perhost *) (mo_ph_node->data);
				if (deliver_msglist_host (route, mo_ph->msgout_list, mo_ph->host, route->resolve_list))
					ok = TRUE;

				destroy_msgout_perhost(mo_ph);
			}
			g_list_free(mo_ph_list);
		}
	}
	return ok;
}

/*
  calls route_prepare_msg()
  delivers messages in msg_list using route by calling deliver_route_msgout_list()
*/
gboolean
deliver_route_msg_list(connect_route * route, GList * msgout_list)
{
	GList *msgout_list_deliver = NULL;
	GList *msgout_node;
	gboolean ok = TRUE;

	DEBUG(6) debugf("deliver_route_msg_list()\n");

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		msg_out *msgout_cloned = clone_msg_out(msgout);
		GList *rcpt_list_non_delivered = NULL;
		GList *rcpt_node;

		/* we have to delete already delivered rcpt's because a previous route may have delivered to it */
		foreach(msgout_cloned->rcpt_list, rcpt_node) {
			address *rcpt = (address *) (rcpt_node->data);
			/* failed addresses already have been bounced - there should be a better way to handle those. */
			if (!addr_is_delivered(rcpt) && !addr_is_failed(rcpt)
			    && !(rcpt->flags & ADDR_FLAG_LAST_ROUTE))
				rcpt_list_non_delivered = g_list_append(rcpt_list_non_delivered, rcpt);
		}
		g_list_free(msgout_cloned->rcpt_list);
		msgout_cloned->rcpt_list = rcpt_list_non_delivered;

		if (msgout_cloned->rcpt_list) {
			if (route_is_allowed_mail_local(route, msgout->msg->return_path)
			   && route_is_allowed_return_path(route, msgout->msg-> return_path)) {
				GList *rcpt_list_allowed = NULL, *rcpt_list_notallowed = NULL;
				msg_rcptlist_route(route, msgout_cloned->rcpt_list, &rcpt_list_allowed, &rcpt_list_notallowed);

				if (rcpt_list_allowed != NULL) {
					logwrite(LOG_NOTICE, "%s using '%s'\n", msgout->msg->uid, route->name);

					g_list_free(msgout_cloned->rcpt_list);
					msgout_cloned->rcpt_list = rcpt_list_allowed;

					if (route->last_route) {
						GList *rcpt_node;
						foreach(msgout_cloned->rcpt_list, rcpt_node) {
							address *rcpt = (address *) (rcpt_node->data);
							rcpt->flags |= ADDR_FLAG_LAST_ROUTE;
						}
					}

					route_prepare_msgout(route, msgout_cloned);
					msgout_list_deliver = g_list_append(msgout_list_deliver, msgout_cloned);
				} else
					destroy_msg_out(msgout_cloned);
			} else
				destroy_msg_out(msgout_cloned);
		} else
			destroy_msg_out(msgout_cloned);
	}

	if (msgout_list_deliver != NULL) {
		if (deliver_route_msgout_list(route, msgout_list_deliver))
			ok = TRUE;
		destroy_msg_out_list(msgout_list_deliver);
	}
	return ok;
}

/* copy pointers of delivered addresses to the msg's non_rcpt_list,
   to make sure that they will not be delivered again.
*/
void
update_non_rcpt_list(msg_out * msgout)
{
	GList *rcpt_node;
	message *msg = msgout->msg;

	foreach(msgout->rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);
		if (addr_is_delivered(rcpt) || addr_is_failed(rcpt))
			msg->non_rcpt_list = g_list_append(msg->non_rcpt_list, rcpt);
	}
}

/* after delivery attempts, we check if there are any rcpt addresses left in the message.
   If all addresses have been completed, the spool files will be deleted,
   otherwise the header spool will be written back.
   We never changed the data spool, so there is no need to write that back.

   returns TRUE if all went well.
*/
gboolean
deliver_finish(msg_out * msgout)
{
	GList *rcpt_node;
	gboolean ok = FALSE;
	message *msg = msgout->msg;
	gboolean finished = TRUE;

	update_non_rcpt_list(msgout);

	/* we NEVER made copies of the addresses, flags affecting addresses
	   were always set on the original address structs */
	foreach(msg->rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);
		if (!addr_is_finished_children(rcpt))
			finished = FALSE;
		else {
			/* if ALL children have been delivered, mark parent as delivered.
			   if there is one or more not delivered, it must have failed, we mark the parent as failed as well.
			 */
			if (addr_is_delivered_children(rcpt)) {
				addr_mark_delivered(rcpt);
			} else {
				addr_mark_failed(rcpt);
			}
		}
	}

	if (!finished) {
		/* one not delivered address was found */
		if (spool_write(msg, FALSE)) {
			ok = TRUE;
			DEBUG(2) debugf("spool header for %s written back.\n", msg->uid);
		} else
			logwrite(LOG_ALERT, "could not write back spool header for %s\n", msg->uid);
	} else {
		ok = spool_delete_all(msg);
		if (ok)
			logwrite(LOG_NOTICE, "%s completed.\n", msg->uid);
	}
	return ok;
}

gboolean
deliver_finish_list(GList * msgout_list)
{
	gboolean ok = TRUE;
	GList *msgout_node;
	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		if (!deliver_finish(msgout))
			ok = FALSE;
	}
	return ok;
}

gboolean
deliver_msgout_list_online(GList * msgout_list)
{
	GList *rf_list = NULL;
	gchar *connect_name = detect_online();
	gboolean ok = FALSE;

	if (connect_name != NULL) {
		logwrite(LOG_NOTICE, "detected online configuration %s\n", connect_name);
		/* we are online! */
		rf_list = (GList *) table_find(conf.connect_routes, connect_name);
		if (rf_list != NULL) {
			GList *route_list = read_route_list(rf_list, FALSE);
			if (route_list) {
				GList *route_node;
				foreach(route_list, route_node) {
					connect_route *route = (connect_route *) (route_node->data);
					ok = deliver_route_msg_list(route, msgout_list);
				}
				destroy_route_list(route_list);
			} else
				logwrite(LOG_ALERT, "could not read route list '%s'\n", connect_name);
		} else {
			logwrite(LOG_ALERT, "route list with name '%s' not found.\n", connect_name);
		}
	}
	return ok;
}

gboolean
deliver_msg_list(GList * msg_list, guint flags)
{
	GList *msgout_list = create_msg_out_list(msg_list);
	GList *local_msgout_list = NULL, *localnet_msgout_list = NULL, *other_msgout_list = NULL;
	GList *msgout_node;
	GList *alias_table = NULL;
	gboolean ok = TRUE;

	if (conf.alias_file) {
		alias_table = table_read(conf.alias_file, ':');
	}

	/* sort messages for different deliveries */
	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		GList *rcpt_list;
		GList *local_rcpt_list = NULL;
		GList *localnet_rcpt_list = NULL;
		GList *other_rcpt_list;

		if (!spool_lock(msgout->msg->uid))
			continue;

		rcpt_list = g_list_copy(msgout->msg->rcpt_list);
		if (conf.log_user) {
			address *addr = create_address_qualified(conf.log_user, TRUE, conf.host_name);
			if (addr)
				rcpt_list = g_list_prepend(rcpt_list, addr);
		}
		if (alias_table) {
			GList *aliased_rcpt_list;
			aliased_rcpt_list = alias_expand(alias_table, rcpt_list, msgout->msg->non_rcpt_list);
			g_list_free(rcpt_list);
			rcpt_list = aliased_rcpt_list;
		}

		/* local recipients */
		other_rcpt_list = NULL;
		rcptlist_with_addr_is_local(rcpt_list, &local_rcpt_list, &other_rcpt_list);

		if (flags & DLVR_LOCAL) {
			if (local_rcpt_list != NULL) {
				msg_out *local_msgout = clone_msg_out(msgout);
				local_msgout->rcpt_list = local_rcpt_list;
				local_msgout_list = g_list_append(local_msgout_list, local_msgout);
			}
		}

		g_list_free(rcpt_list);

		/* local net recipients */
		rcpt_list = other_rcpt_list;
		other_rcpt_list = NULL;
		rcptlist_with_one_of_hostlist(rcpt_list, conf.local_nets, &localnet_rcpt_list, &other_rcpt_list);

		if (flags & DLVR_LAN) {
			if (localnet_rcpt_list != NULL) {
				msg_out *localnet_msgout = clone_msg_out(msgout);
				localnet_msgout->rcpt_list = localnet_rcpt_list;
				localnet_msgout_list = g_list_append(localnet_msgout_list, localnet_msgout);
			}
		}

		if (flags & DLVR_ONLINE) {
			/* the rest, this is online delivery */
			if (other_rcpt_list != NULL) {
				msg_out *other_msgout = clone_msg_out(msgout);
				other_msgout->rcpt_list = other_rcpt_list;
				other_msgout_list = g_list_append(other_msgout_list, other_msgout);
			}
		}
	}

	if (alias_table)
		destroy_table(alias_table);

	/* actual delivery */
	if (local_msgout_list != NULL) {
		foreach(local_msgout_list, msgout_node) {
			msg_out *msgout = (msg_out *) (msgout_node->data);
			if (!deliver_local(msgout))
				ok = FALSE;
		}
		destroy_msg_out_list(local_msgout_list);
	}

	if (localnet_msgout_list != NULL) {
		GList *route_list = NULL;
		GList *route_node;

		if (conf.local_net_routes)
			route_list = read_route_list(conf.local_net_routes, TRUE);
		else
			route_list = g_list_append(NULL, create_local_route());

		foreach(route_list, route_node) {
			connect_route *route = (connect_route *) (route_node->data);
			if (!deliver_route_msg_list(route, localnet_msgout_list))
				ok = FALSE;
		}
		destroy_msg_out_list(localnet_msgout_list);
		destroy_route_list(route_list);
	}

	if (other_msgout_list != NULL) {
		if (!deliver_msgout_list_online(other_msgout_list))
			ok = FALSE;
		destroy_msg_out_list(other_msgout_list);
	}

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		spool_unlock(msgout->msg->uid);
	}

	destroy_msg_out_list(msgout_list);

	return ok;
}

/* This function searches in the list of rcpt addresses
   for local and 'local net' addresses. Remote addresses
   which are reachable only when online are treated specially
   in another function.

   deliver() is called when a message has just been received and should
   be delivered immediately.
*/
gboolean
deliver(message * msg)
{
	gboolean ok;
	GList *msg_list = g_list_append(NULL, msg);

	ok = deliver_msg_list(msg_list, DLVR_ALL);
	g_list_free(msg_list);

	return ok;
}
