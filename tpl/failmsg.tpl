Subject: Mail Delivery Failure Notice
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

Sorry, but your mail could not be delivered to all recipients.
Delivery to the following recipients failed permanently and has been given
up:

@failed_rcpts

This error message may give you a hint about what caused the
failure:

${err_msg}

If you need help, write to <postmaster@${host_name}>.

Your message follows attached, including all headers:

--${uid}/${host_name}
Content-Description: Undelivered Message
Content-Type: message/rfc822

@msg_headers

@msg_body

--${uid}/${host_name}--
