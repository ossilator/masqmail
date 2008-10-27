#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include "base64.h"

int
main()
{
	gchar line[100];
	gchar *buf;
	gint size;

	while (fgets(line, 100, stdin)) {
		buf = base64_decode(line, &size);
		fwrite(buf, size, 1, stdout);
		g_free(buf);
	}
	exit(0);
}
