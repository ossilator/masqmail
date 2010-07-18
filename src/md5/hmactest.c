#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "global.h"
#include "md5.h"
#include "hmac_md5.h"

static void
pad0_copy(char *d, char *s, int sz)
{
	int i = 0;
	while (*s && (i < sz)) {
		*(d++) = *(s++);
		i++;
	}
	while (i <= sz) {
		*(d++) = 0;
		i++;
	}
}

int
main()
{
	int i;
	/*  unsigned char digest[16]; */
	char digest[16];
	char *msgid = "<1896.697170952@postoffice.reston.mci.net>";
	char secret[65];

	hmac_md5("<48157.953508124@mail.class-c.net>", 34, "no!SpamAtAll", 12, digest);
	for (i = 0; i < 16; i++)
		printf("%x", (unsigned int) digest[i]);
	printf("\n");

	hmac_md5(msgid, strlen(msgid), "tanstaaftanstaaf", 16, digest);
	for (i = 0; i < 16; i++)
		printf("%x", (unsigned int) digest[i]);
	printf("\n");

	pad0_copy(secret, "tanstaaftanstaaf", 64);
	hmac_md5(msgid, strlen(msgid), secret, 64, digest);
	for (i = 0; i < 16; i++)
		printf("%x", (unsigned int) digest[i]);
	printf("\n");

	exit(0);
}
