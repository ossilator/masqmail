Subject: Warning: could not yet send message
From: MAILER-DAEMON@${host_name}
To: ${return_path}
MIME-Version: 1.0
Content-Type: multipart/mixed;
        boundary="${uid}/${host_name}"

This is a MIME-encapsulated message.

--${uid}/${host_name}
Content-Description: Notification
Content-Type: text/plain

This message was sent to you by the mailer daemon (${package} ${version})
at ${host_name}.

Sorry, but your mail could not yet be delivered to all recipients.
Delivery to the following recipients has been defered:

@failed_rcpts

Delivery will be tried again, until it is either successfull or a
timeout has been reached. If the latter happens, you will get a
delivery failure notice.


This error message may give you a hint about what caused the
delay:

${err_msg}

If you need help, write to <postmaster@${host_name}>.

The headers of your message follow attached:

--${uid}/${host_name}
Content-Description: Undelivered Message Headers
Content-Type: message/rfc822

@msg_headers

--${uid}/${host_name}--
