
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"

int main()
{
  gchar in[58];
  gint size;

  do{
    gchar *out;

    size = fread(in, 1, 54, stdin);
    out = base64_encode(in, size);
    fputs(out, stdout);
    putchar('\n');
    g_free(out);
  }while(size == 54);
  exit(0);
}

