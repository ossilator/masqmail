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
#include "smtp_out.h"

masqmail_conf conf;

void logwrite(int pri, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vprintf(fmt, args);

  va_end(args);
}

void debugf(const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  vfprintf(stderr, fmt, args);
  fflush(stderr);

  va_end(args);
}

int main(int argc, char *argv[])
{
  int arg;
  accept_error err;
  message *msg = NULL;
  GList *resolve_list =
    g_list_append(NULL, resolve_byname);

  msg = create_message();
  if(msg == NULL) exit(EXIT_FAILURE);
  msg->received_host = NULL;
  msg->return_path = NULL;
  msg->received_prot = PROT_LOCAL;

  conf.host_name = g_strdup("localhost");
  conf.curr_route = NULL;
  conf.debug_level = 7;

  for(arg = 1; arg < argc; arg++){
    address *adr;
    msg->rcpt_list =
      g_list_append(msg->rcpt_list,
		    adr = create_address_qualified(g_strdup(argv[arg]),
						   TRUE, g_strdup("localhost")));
  }
  if((err =
      accept_message(stdin, msg, ACC_HEAD_FROM_RCPT|ACC_NODOT_TERM|ACC_NO_RECVD_HDR))
      == AERR_OK){

    if(smtp_deliver("localhost", 25, resolve_list, msg, NULL, NULL) == smtp_ok)
      exit(EXIT_SUCCESS);
    else
      debugf("smtp_deliver failed.\n");
  }else{
    debugf("accept_message failed.\n");
  }
  exit(EXIT_FAILURE);
}

