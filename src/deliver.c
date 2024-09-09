// SPDX-FileCopyrightText: (C) 1999-2002 Oliver Kurth
// SPDX-FileCopyrightText: (C) 2008,2010 markus schnalke <meillo@marmaro.de>
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#include "smtp_out.h"

#include <assert.h>
#include <fnmatch.h>
#include <sysexits.h>
#include <netdb.h>

static void deliver_finish(msg_out *msgout);

/*
**  collect failed/defered rcpts for failure/warning messages
**  returns TRUE if either there are no failures or a failure message has
**  been successfully sent
*/
static gboolean
delivery_failures(message *msg, GList *rcpt_list, gchar *err_fmt, ...)
{
	gboolean ok_fail = TRUE, ok_warn = TRUE;
	time_t now = time(NULL);

	GList *failed_list = NULL, *defered_list = NULL, *rcpt_node;
	va_list args;
	va_start(args, err_fmt);

	foreach(rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);

		if (addr_is_defered(rcpt)) {
			if ((now - msg->received_time) >= conf.max_defer_time){
				addr_mark_failed(rcpt);
			} else {
				defered_list = g_list_prepend(defered_list,
						rcpt);
			}
		}
		if (addr_is_failed(rcpt)) {
			failed_list = g_list_prepend(failed_list, rcpt);
		}
	}
	if (failed_list) {
		ok_fail = fail_msg(msg, conf.errmsg_file, failed_list,
				err_fmt, args);
		g_list_free(failed_list);
	}
	if (defered_list) {
		ok_warn = warn_msg(msg, conf.warnmsg_file, defered_list,
				err_fmt, args);
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

static gboolean
deliver_local_mbox(message *msg, GList *hdr_list, address *rcpt,
		address *env_addr)
{
	DEBUG(1) debugf("attempting to deliver %s with mbox\n", msg->uid);
	if (append_file(msg, hdr_list, rcpt->local_part)) {
		if (env_addr != rcpt) {
			logwrite(LOG_INFO, "%s => %s@%s <%s@%s> with mbox\n",
					msg->uid, rcpt->local_part,
					rcpt->domain, env_addr->local_part,
					env_addr->domain);
		} else {
			logwrite(LOG_INFO, "%s => <%s@%s> with mbox\n",
					msg->uid, rcpt->local_part,
					rcpt->domain);
		}
		addr_mark_delivered(rcpt);
		return TRUE;
	}

	/* prevents 'Resource temporarily unavailable (11)' */
	if (errno != EAGAIN) {
		addr_mark_failed(rcpt);
	} else {
		addr_mark_defered(rcpt);
	}
	return FALSE;
}

static gboolean
deliver_local_pipe(message *msg, GList *hdr_list, address *rcpt,
		address *env_addr)
{
	guint flags = 0;

	DEBUG(1) debugf("attempting to deliver %s with pipe\n", msg->uid);

	flags |= (conf.pipe_fromline) ? MSGSTR_FROMLINE : 0;
	flags |= (conf.pipe_fromhack) ? MSGSTR_FROMHACK : 0;
	if (pipe_out(msg, hdr_list, rcpt, &(rcpt->local_part[1]), flags)) {
		logwrite(LOG_INFO, "%s => %s <%s@%s> with pipe\n",
				msg->uid, rcpt->local_part,
				env_addr->local_part, env_addr->domain);
		addr_mark_delivered(rcpt);
		return TRUE;
	}

	if ((errno != (1024 + EX_TEMPFAIL)) && (errno != EAGAIN)) {
		addr_mark_failed(rcpt);
	} else {
		addr_mark_defered(rcpt);
		/* has no effect yet, except that mail remains in spool */
	}
	return FALSE;
}

static gboolean
deliver_local_mda(message *msg, GList *hdr_list, address *rcpt)
{
	gboolean ok = FALSE;
	GList *var_table = var_table_rcpt(var_table_msg(NULL, msg), rcpt);
	guint flags = 0;
	gchar cmd[256];

	DEBUG(1) debugf("attempting to deliver %s with mda\n", msg->uid);

	if (!expand(var_table, conf.mda, cmd, 256)) {
		logwrite(LOG_ERR, "could not expand string %s\n", conf.mda);
		destroy_table(var_table);
		return FALSE;
	}

	flags |= (conf.mda_fromline) ? MSGSTR_FROMLINE : 0;
	flags |= (conf.mda_fromhack) ? MSGSTR_FROMHACK : 0;
	if (pipe_out(msg, hdr_list, rcpt, cmd, flags)) {
		logwrite(LOG_INFO, "%s => %s@%s with mda (cmd = '%s')\n",
				msg->uid, rcpt->local_part, rcpt->domain, cmd);
		addr_mark_delivered(rcpt);
		ok = TRUE;
	} else if ((errno != (1024 + EX_TEMPFAIL)) && (errno != EAGAIN)) {
		addr_mark_failed(rcpt);
	} else {
		addr_mark_defered(rcpt);
		/* has no effect yet, except that mail remains in spool */
	}

	destroy_table(var_table);
	return ok;
}

static void
deliver_local(msg_out *msgout)
{
	message *msg = msgout->msg;
	GList *rcpt_list = msgout->rcpt_list;
	GList *rcpt_node;
	gboolean ok = FALSE, flag = FALSE, ok_fail = FALSE;

	DEBUG(5) debugf("deliver_local entered\n");

	flag = (msg->data_list == NULL);
	if (flag && !spool_read_data(msg)) {
		logwrite(LOG_ERR, "could not open data spool file for %s\n",
				msg->uid);
		return;
	}

	for (rcpt_node = g_list_first(rcpt_list); rcpt_node;
			rcpt_node = g_list_next(rcpt_node)) {
		GList *hdr_list;
		address *rcpt = (address *) (rcpt_node->data);
		address *env_addr = addr_find_ancestor(rcpt);
		address *ret_path = msg->return_path;
		header *retpath_hdr, *envto_hdr;

		/*
		**  we need a private copy of the hdr list because we add
		**  headers here that belong to the rcpt only. g_list_copy
		**  copies only the nodes, so it is safe to g_list_free it
		*/
		hdr_list = g_list_copy(msg->hdr_list);
		retpath_hdr = create_header(HEAD_ENVELOPE_TO,
				"Envelope-to: %s\n", addr_string(env_addr));
		envto_hdr = create_header(HEAD_RETURN_PATH,
				"Return-path: %s\n", addr_string(ret_path));

		hdr_list = g_list_prepend(hdr_list, envto_hdr);
		hdr_list = g_list_prepend(hdr_list, retpath_hdr);

		if (*rcpt->local_part == '|') {
			/*
			**  probably for expanded aliases, but why not done
			**  like with the mda? //meillo 2010-12-06
			*/
			if (deliver_local_pipe(msg, hdr_list, rcpt,
					env_addr)) {
				ok = TRUE;
			}
		} else {
			/* figure out which mailbox type should be used
			** for this user */
			gchar *user = rcpt->local_part;
			gchar *mbox_type = conf.mbox_default;

			if (g_list_find_custom(conf.mbox_users, user,
					_g_list_strcasecmp)) {
				mbox_type = "mbox";
			} else if (g_list_find_custom (conf.mda_users, user,
					_g_list_strcasecmp)) {
				mbox_type = "mda";
			}

			if (strcmp(mbox_type, "mbox")==0) {
				if (deliver_local_mbox(msg, hdr_list, rcpt,
						env_addr)) {
					ok = TRUE;
				}
			} else if (strcmp(mbox_type, "mda") == 0) {
				if (conf.mda) {
					if (deliver_local_mda(msg, hdr_list, rcpt)) {
						ok = TRUE;
					}
				} else {
					logwrite(LOG_ERR, "mbox type is mda, but no mda "
					         "command given in configuration\n");
				}

			} else {
				logwrite(LOG_ERR, "unknown mbox type '%s'\n", mbox_type);
			}
		}

		destroy_header(retpath_hdr);
		destroy_header(envto_hdr);

		g_list_free(hdr_list);
	}
	ok_fail = delivery_failures(msg, rcpt_list, "%s (%d)",
			ext_strerror(errno), errno);

	if (flag) {
		msg_free_data(msg);
	}
	if (ok || ok_fail) {
		deliver_finish(msgout);
	}
}

static gboolean
deliver_msglist_host_pipe(connect_route *route, GList *msgout_list)
{
	gboolean ok = TRUE;
	GList *msgout_node;

	DEBUG(5) debugf("deliver_msglist_host_pipe entered\n");

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		gboolean flag, ok_fail = FALSE;
		message *msg = msgout->msg;
		GList *rcpt_node, *rcpt_list = msgout->rcpt_list;

		DEBUG(1) debugf("attempting to deliver %s with pipe\n",
				msg->uid);

		flag = (msg->data_list == NULL);
		if (flag && !spool_read_data(msg)) {
			logwrite(LOG_ERR, "could not open data spool file for %s\n", msg->uid);
			continue;
		}

		ok = FALSE;
		foreach(rcpt_list, rcpt_node) {
			address *rcpt = (address *) (rcpt_node->data);
			gchar cmd[256];
			GList *var_table = var_table_rcpt(var_table_msg(NULL,
					msg), rcpt);

			DEBUG(1) debugf("attempting to deliver %s to %s@%s "
					"with pipe\n", msg->uid,
					rcpt->local_part, rcpt->domain);

			if (!expand(var_table, route->pipe, cmd, 256)) {
				logwrite(LOG_ERR, "could not expand string `%s'\n", route->pipe);
				destroy_table(var_table);
				continue;
			}

			if (pipe_out(msg, msg->hdr_list, rcpt, cmd, (route->pipe_fromline ? MSGSTR_FROMLINE : 0)
			    | (route->pipe_fromhack ? MSGSTR_FROMHACK : 0))) {
				logwrite(LOG_INFO, "%s => %s@%s with pipe (cmd = '%s')\n",
					 msg->uid, rcpt->local_part, rcpt->domain, cmd);
				addr_mark_delivered(rcpt);
				ok = TRUE;
			} else {
				if (route->connect_error_fail) {
					addr_mark_failed(rcpt);
				} else {
					addr_mark_defered(rcpt);
				}
			}

			destroy_table(var_table);
		}
		ok_fail = delivery_failures(msg, rcpt_list, "%s", strerror(errno));

		if (flag) {
			msg_free_data(msg);
		}
		if (ok || ok_fail) {
			deliver_finish(msgout);
		}
	}

	return ok;
}

/*
**  deliver list of messages to one host and finishes them if the message was
**  delivered to at least one rcpt.
**  Returns TRUE if at least one msg was delivered to at least one rcpt.
*/
static gboolean
deliver_msglist_host_smtp(connect_route *route, GList *msgout_list,
		gchar *host, GList *res_list)
{
	gboolean ok = FALSE;
	GList *msgout_node;
	smtp_base *psb;
	gint port = 25;

	assert(msgout_list);

	if (!host) {
		/* XXX: what if mail_host isn't set? Is this possible? */
		host = route->mail_host->address;
		port = route->mail_host->port;
	}

	if (route->wrapper) {
		psb = smtp_out_open_child(route->wrapper);
		if (psb) {
			psb->remote_host = host;
		}
	} else {
		psb = smtp_out_open(host, port, res_list);
	}

	if (!psb) {
		/* smtp_out_open() failed */
		foreach(msgout_list, msgout_node) {
			msg_out *msgout = (msg_out *) (msgout_node->data);
			GList *rcpt_node;

			for (rcpt_node = g_list_first(msgout->rcpt_list);
					rcpt_node;
					rcpt_node = g_list_next(rcpt_node)) {
				address *rcpt = (address *) (rcpt_node->data);
				gboolean ret = FALSE;

				addr_unmark_delivered(rcpt);
				if (route->connect_error_fail) {
					addr_mark_failed(rcpt);
				} else {
					addr_mark_defered(rcpt);
				}
				if (route->wrapper) {
					ret = delivery_failures(msgout->msg,
							msgout->rcpt_list,
							"could not open "
							"wrapper:\n\t%s",
							strerror(errno));
				} else {
					ret = delivery_failures(msgout->msg,
							msgout->rcpt_list,
							"could not open "
							"connection to %s:%d "
							":\n\t%s", host, port,
							h_errno != 0 ?
							hstrerror(h_errno) :
							strerror(errno));
				}
				if (ret) {
					deliver_finish(msgout);
				}
			}
		}
		return ok;
	}

	set_heloname(psb, route->helo_name ? route->helo_name : conf.host_name,
			route->do_correct_helo);

#ifdef ENABLE_AUTH
	if (route->auth_name && route->auth_login && route->auth_secret) {
		set_auth(psb, route->auth_name, route->auth_login,
				route->auth_secret);
	}
#endif
	if (!smtp_out_init(psb, route->instant_helo)) {
		/* smtp_out_init() failed */
		smtp_out_quit(psb);
		if ((psb->error==smtp_fail) || (psb->error==smtp_trylater) ||
				(psb->error==smtp_syntax)) {

			foreach(msgout_list, msgout_node) {
				msg_out *msgout =
						(msg_out *)(msgout_node->data);
				smtp_out_mark_rcpts(psb, msgout->rcpt_list);

				if (delivery_failures(msgout->msg,
						msgout->rcpt_list,
						"while connected with %s, "
						"the server replied\n\t%s",
						(route->wrapper) ?
						"<wrapper>" : host,
						psb->buffer)) {
					deliver_finish(msgout);
				}
			}
		}
		destroy_smtpbase(psb);
		return ok;
	}

	if (!route->do_pipelining) {
		psb->use_pipelining = FALSE;
	}

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		gboolean flag, ok_msg = FALSE, ok_fail = FALSE;
		message *msg = msgout->msg;

		/* we may have to read the data at this point
		** and remember if we did */
		flag = (msg->data_list == NULL);
		if (flag && !spool_read_data(msg)) {
			logwrite(LOG_ERR, "could not open data spool file %s\n", msg->uid);
			break;
		}

		smtp_out_msg(psb, msg, msgout->return_path, msgout->rcpt_list,
				msgout->hdr_list);

		ok_fail = delivery_failures(msg, msgout->rcpt_list,
				"while connected with %s, the server "
				"replied\n\t%s", (route->wrapper) ?
				"<wrapper>" : host, psb->buffer);

		if ((psb->error == smtp_eof) || (psb->error == smtp_timeout)) {
			/* connection lost */
			break;
		} else if (psb->error != smtp_ok) {
			if (g_list_next(msgout_node) && !smtp_out_rset(psb)) {
				break;
			}
		}
		ok_msg = (psb->error == smtp_ok);

		if (flag) {
			msg_free_data(msg);
		}
		if (ok_msg) {
			ok = TRUE;
		}
		if (ok_msg || ok_fail) {
			deliver_finish(msgout);
		}
	}
	smtp_out_quit(psb);
	destroy_smtpbase(psb);
	return ok;
}

static gboolean
deliver_msglist_host(connect_route *route, GList *msgout_list, gchar *host,
		GList *res_list)
{

	if (route->pipe) {
		DEBUG(5) debugf("with pipe\n");
		return deliver_msglist_host_pipe(route, msgout_list);
	} else {
		DEBUG(5) debugf("with smtp\n");
		return deliver_msglist_host_smtp(route, msgout_list,
				host, res_list);
	}
}

/*
** delivers messages in msgout_list using route
*/
static void
deliver_route_msgout_list(connect_route *route, GList *msgout_list)
{
	GList *mo_ph_list;
	GList *mo_ph_node;

	DEBUG(5) debugf("deliver_route_msgout_list entered, route->name=%s\n",
			route->name);

	if (route->mail_host) {
		/* easy: deliver everything to a smart host for relay */
		deliver_msglist_host(route, msgout_list, NULL, route->resolve_list);
		return;
	}

	/* this is not easy... */

	mo_ph_list = route_msgout_list(msgout_list);
	/* okay, now we have ordered our messages by the hosts. */
	if (!mo_ph_list) {
		return;
	}

	/*
	**  TODO: It would be nice to be able to fork for each host.
	**  We cannot do that yet because of complications with finishing the
	**  messages. Threads could be a solution because they use the same
	**  memory. But we are not thread safe yet...
	*/
	foreach(mo_ph_list, mo_ph_node) {
		msgout_perhost *mo_ph = (msgout_perhost *) (mo_ph_node->data);
		deliver_msglist_host(route, mo_ph->msgout_list, mo_ph->host, route->resolve_list);
	}
	g_list_free_full(mo_ph_list, (GDestroyNotify) destroy_msgout_perhost);
}

/*
** calls route_prepare_msg()
** delivers messages in msg_list using route by calling
** deliver_route_msgout_list()
*/
static void
deliver_route_msg_list(connect_route *route, GList *msgout_list)
{
	GList *msgout_list_deliver = NULL;
	GList *msgout_node;

	DEBUG(6) debugf("deliver_route_msg_list()\n");

	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		msg_out *msgout_cloned = clone_msg_out(msgout);
		GList *rcpt_list_non_delivered = NULL;
		GList *rcpt_node;

		/*
		**  we have to delete already delivered rcpt's because a
		**  previous route may have delivered to it
		*/
		foreach(msgout_cloned->rcpt_list, rcpt_node) {
			address *rcpt = (address *) (rcpt_node->data);
			/*
			**  failed addresses already have been bounced;
			**  there should be a better way to handle those.
			*/
			if (!addr_is_delivered(rcpt) &&
					!addr_is_failed(rcpt) &&
					!(rcpt->flags & ADDR_FLAG_LAST_ROUTE)){
				rcpt_list_non_delivered = g_list_append(rcpt_list_non_delivered, rcpt);
			}
		}
		g_list_free(msgout_cloned->rcpt_list);
		msgout_cloned->rcpt_list = rcpt_list_non_delivered;

		if (!msgout_cloned->rcpt_list) {
			destroy_msg_out(msgout_cloned);
			continue;
		}

		/* filter by allowed envelope sender */
		if (!route_sender_is_allowed(route, msgout->msg->return_path)){
			DEBUG(6) debugf("sender `%s' is not allowed for this route\n",
			                msgout->msg->return_path->address);
			destroy_msg_out(msgout_cloned);
			continue;
		}

		/* filter by allowed envelope rcpts */
		GList *rcpt_list_allowed = NULL;
		GList *rcpt_list_notallowed = NULL;
		route_split_rcpts(route, msgout_cloned->rcpt_list,
				&rcpt_list_allowed, &rcpt_list_notallowed);
		if (!rcpt_list_allowed) {
			destroy_msg_out(msgout_cloned);
			continue;
		}

		/* filter by allowed from header */
		if (route->denied_from_hdrs || route->allowed_from_hdrs) {
			header *from_hdr = find_header(msgout->msg->hdr_list, HEAD_FROM);
			if (from_hdr) {
				address *addr = create_address_qualified(
						from_hdr->value, FALSE, conf.host_name);
				gboolean isok = route_from_hdr_is_allowed(route, addr);
				destroy_address(addr);
				if (!isok) {
					DEBUG(6) debugf("from hdr `%s' is not allowed for this route\n",
					                from_hdr->value);
					destroy_msg_out(msgout_cloned);
					continue;
				}
			}
		}

		logwrite(LOG_INFO, "%s using '%s'\n", msgout->msg->uid, route->name);

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
		msgout_list_deliver = g_list_append(msgout_list_deliver,
				msgout_cloned);
	}

	if (msgout_list_deliver) {
		deliver_route_msgout_list(route, msgout_list_deliver);
		destroy_msg_out_list(msgout_list_deliver);
	}
}

/*
**  copy pointers of delivered addresses to the msg's non_rcpt_list,
**  to make sure that they will not be delivered again.
*/
static void
update_non_rcpt_list(msg_out *msgout)
{
	GList *rcpt_node;
	message *msg = msgout->msg;

	foreach(msgout->rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);
		if (addr_is_delivered(rcpt) || addr_is_failed(rcpt)) {
			msg->non_rcpt_list = g_list_append(msg->non_rcpt_list,
					rcpt);
		}
	}
}

/*
**  after delivery attempts, we check if there are any rcpt addresses left in
**  the message. If all addresses have been completed, the spool files will be
**  deleted, otherwise the header spool will be written back. We never changed
**  the data spool, so there is no need to write that back.
**
**  returns TRUE if all went well.
*/
static void
deliver_finish(msg_out *msgout)
{
	GList *rcpt_node;
	message *msg = msgout->msg;
	gboolean finished = TRUE;

	update_non_rcpt_list(msgout);

	/*
	**  we NEVER made copies of the addresses, flags affecting addresses
	**  were always set on the original address structs
	*/
	foreach(msg->rcpt_list, rcpt_node) {
		address *rcpt = (address *) (rcpt_node->data);
		if (!addr_is_finished_children(rcpt)) {
			finished = FALSE;
		} else {
			/*
			**  if ALL children have been delivered, mark parent as
			**  delivered. if there is one or more not delivered,
			**  it must have failed, we mark the parent as failed
			**  as well.
			*/
			if (addr_is_delivered_children(rcpt)) {
				addr_mark_delivered(rcpt);
			} else {
				addr_mark_failed(rcpt);
			}
		}
	}

	if (finished) {
		spool_delete_all(msg);
		logwrite(LOG_INFO, "%s completed.\n", msg->uid);
		return;
	}

	/* one not delivered address was found */
	if (!spool_write(msg, FALSE)) {
		logwrite(LOG_ERR, "could not write back spool header "
				"for %s\n", msg->uid);
		return;
	}

	DEBUG(2) debugf("spool header for %s written back.\n", msg->uid);
	return;
}

static void
deliver_remote(GList *remote_msgout_list)
{
	GList *route_list = NULL;
	GList *route_node;
	GList *rf_list = NULL;
	gchar *connect_name = NULL;

	if (!remote_msgout_list) {
		return;
	}

	/* perma routes */
	if (conf.perma_routes) {
		DEBUG(5) debugf("processing perma_routes\n");

		route_list = read_route_list(conf.perma_routes);
		foreach(route_list, route_node) {
			connect_route *route =
					(connect_route *) (route_node->data);
			deliver_route_msg_list(route, remote_msgout_list);
		}
		destroy_route_list(route_list);
	}

	/* query routes */
	connect_name = online_query();
	if (!connect_name) {
		DEBUG(5) debugf("online query returned false\n");
		return;
	}

	/* we are online! */
	DEBUG(5) debugf("processing query_routes\n");
	logwrite(LOG_INFO, "detected online configuration `%s'\n",
			connect_name);

	rf_list = (GList *) table_find(conf.query_routes, connect_name);
	if (!rf_list) {
		logwrite(LOG_ERR, "route list with name '%s' not found.\n",
				connect_name);
		return;
	}

	route_list = read_route_list(rf_list);
	if (!route_list) {
		logwrite(LOG_ERR, "could not read route list '%s'\n",
				connect_name);
		return;
	}

	foreach(route_list, route_node) {
		connect_route *route = (connect_route *) (route_node->data);
		deliver_route_msg_list(route, remote_msgout_list);
	}
	destroy_route_list(route_list);
}

/*
**  This function splits the list of rcpt addresses
**  into local and remote addresses and processes them accordingly.
*/
void
deliver_msg_list(GList *msg_list, guint flags)
{
	GList *msgout_list = NULL;
	GList *msg_node;
	GList *local_msgout_list = NULL;
	GList *remote_msgout_list = NULL;
	GList *msgout_node;
	GList *alias_table = NULL;
	GList *globalias_table = NULL;

	/* create msgout_list */
	foreach(msg_list, msg_node) {
		message *msg = (message *) msg_node->data;
		msgout_list = g_list_append(msgout_list, create_msg_out(msg));
	}

	if (conf.globalias_file) {
		globalias_table = table_read(conf.globalias_file, ':');
	}
	if (conf.alias_file) {
		alias_table = table_read(conf.alias_file, ':');
	}

	/* sort messages for different deliveries */
	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		GList *rcpt_list;
		GList *local_rcpt_list = NULL;
		GList *other_rcpt_list = NULL;

		if (!spool_lock(msgout->msg->uid)) {
			DEBUG(5) debugf("spool_lock(%s) failed.\n",
					msgout->msg->uid);
			continue;
		}
		DEBUG(5) debugf("spool_lock(%s)\n", msgout->msg->uid);

		rcpt_list = g_list_copy(msgout->msg->rcpt_list);
		if (conf.log_user) {
			address *addr = create_address_qualified(conf.log_user,
					TRUE, conf.host_name);
			if (addr) {
				rcpt_list = g_list_prepend(rcpt_list, addr);
			} else {
				logwrite(LOG_ERR, "invalid log_user "
						"address `%s', ignoring\n",
						conf.log_user);
			}
		}
		if (globalias_table) {
			GList *globaliased_rcpt_list;

			DEBUG(5) debugf("Doing globalias expansion\n");
			globaliased_rcpt_list = alias_expand(globalias_table,
					rcpt_list,
					msgout->msg->non_rcpt_list, 1);
			g_list_free(rcpt_list);
			rcpt_list = globaliased_rcpt_list;
		}
		if (alias_table) {
			GList *aliased_rcpt_list;

			DEBUG(5) debugf("Doing alias expansion\n");
			aliased_rcpt_list = alias_expand(alias_table,
					rcpt_list,
					msgout->msg->non_rcpt_list, 0);
			g_list_free(rcpt_list);
			rcpt_list = aliased_rcpt_list;
		}

		/* split_rcpts(rcpt_list, NULL, &local_rcpt_list, NULL,
		** &other_rcpt_list); */
		local_rcpt_list = local_rcpts(rcpt_list);
		other_rcpt_list = remote_rcpts(rcpt_list);
		g_list_free(rcpt_list);

		/* local recipients */
		if ((flags & DLVR_LOCAL) && local_rcpt_list) {
			msg_out *local_msgout = clone_msg_out(msgout);
			local_msgout->rcpt_list = local_rcpt_list;
			local_msgout_list = g_list_append(local_msgout_list,
					local_msgout);
		}

		/* remote recipients, requires online delivery  */
		if ((flags & DLVR_ONLINE) && other_rcpt_list) {
			msg_out *remote_msgout = clone_msg_out(msgout);
			remote_msgout->rcpt_list = other_rcpt_list;
			remote_msgout_list = g_list_append(remote_msgout_list,
					remote_msgout);
		}
	}

	destroy_table(alias_table);
	destroy_table(globalias_table);

	/* process local/remote msgout lists -> delivery */

	if (local_msgout_list) {
		DEBUG(5) debugf("local_msgout_list\n");
		foreach(local_msgout_list, msgout_node) {
			msg_out *msgout = (msg_out *) (msgout_node->data);
			deliver_local(msgout);
		}
		destroy_msg_out_list(local_msgout_list);
	}

	if (remote_msgout_list) {
		DEBUG(5) debugf("remote_msgout_list\n");
		deliver_remote(remote_msgout_list);
		destroy_msg_out_list(remote_msgout_list);
	}

	/* unlock spool files */
	foreach(msgout_list, msgout_node) {
		msg_out *msgout = (msg_out *) (msgout_node->data);
		DEBUG(5) debugf("spool_unlock(%s)\n", msgout->msg->uid);
		spool_unlock(msgout->msg->uid);
	}
	destroy_msg_out_list(msgout_list);
}

static void
do_deliver(message *msg)
{
	GList *msg_list = g_list_append(NULL, msg);
	deliver_msg_list(msg_list, DLVR_ALL);
	g_list_free(msg_list);
}

/*
**  deliver() is called when a message has just been received
**  (mode_accept and smtp_in) and should be delivered immediately
**  (neither -odq nor do_queue). Only this one message will be tried to
**  deliver then.
*/
void
deliver(message *msg)
{
	if (!conf.do_background) {
		do_deliver(msg);
		return;
	}

	pid_t pid = fork();
	if (pid < 0) {
		logerrno(LOG_ERR, "could not fork for delivery");
		return;
	}
	if (pid != 0) {
		// parent
		return;
	}
	// child
	null_stdio();

	do_deliver(msg);

	exit(0);
}
