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
  
  GList *alias_table, *table_node;
  GList *adr_list = NULL, *adr_node;
  GList *alias_list, *alias_node;

  conf.host_name = g_strdup("localhost");
  conf.local_hosts = g_list_append(NULL, g_strdup("localhost"));
  conf.debug_level = 0;

  for(arg = 1; arg < argc; arg++){
    address *adr;
    adr_list =
      g_list_append(adr_list,
		    adr = create_address_qualified(g_strdup(argv[arg]),
						   TRUE, g_strdup("localhost")));
    //    printf("%s@%s\n", adr->local_part, adr->domain);
  }

  alias_table = table_read("/etc/aliases", ':');

  foreach(alias_table, table_node){
    table_pair *pair = (table_pair *)(table_node->data);
    //    printf("key: %s, value: %s\n", pair->key, pair->value);
  }

  alias_list = alias_expand(alias_table, adr_list, NULL);

  foreach(alias_list, alias_node){
    address *adr = (address *)(alias_node->data);
    printf("%s@%s\n", adr->local_part, adr->domain);
  }
}


