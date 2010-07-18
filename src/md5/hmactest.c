#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include "md5.h"
#include "hmac_md5.h"

/*
instead of pad0_copy(d, s, sz) use:
	memset(d, 0, sz);
	memcpy(d, s, strlen(s));

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
*/

int
main()
{
	int i;
	char digest[16];
	char *msgid = "<1896.697170952@postoffice.reston.mci.net>";
	char secret[65];


	hmac_md5("<48157.953508124@mail.class-c.net>", 34, "no!SpamAtAll", 12, digest);
	for (i = 0; i < 16; i++)
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	printf("\n\n");


	puts("---- The next two should be equal");


	hmac_md5(msgid, strlen(msgid), "tanstaaftanstaaf", 16, digest);
	for (i = 0; i < 16; i++)
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	printf("\n\n");


	/* pad0_copy(secret, "tanstaaftanstaaf", 64); */
	/* let's do it easier ... */
	memset(secret, 0, sizeof(secret));
	memcpy(secret, "tanstaaftanstaaf", 16);
	hmac_md5(msgid, strlen(msgid), secret, 64, digest);
	for (i = 0; i < 16; i++)
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	printf("\n\n");


	puts("---- Following are the test vectors from RFC 2104");


	char* d01 = "Hi There";
	char k01[16];
	for (i=0; i<16; i++) {
		k01[i] = 0x0b;
	}
	printf("9294727a3638bb1c13f48ef8158bfc9d (should be)\n");
	hmac_md5(d01, strlen(d01), k01, sizeof(k01), digest);
	for (i = 0; i < 16; i++) {
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	}
	printf(" (was computed)\n\n");


	char* d02 = "what do ya want for nothing?";
	char* k02 = "Jefe";
	printf("750c783e6ab0b503eaa86e310a5db738 (should be)\n");
	hmac_md5(d02, strlen(d02), k02, strlen(k02), digest);
	for (i = 0; i < 16; i++) {
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	}
	printf(" (was computed)\n\n");


	char d03[50];
	for (i=0; i<sizeof(d03); i++) {
		d03[i] = 0xdd;
	}
	char k03[16];
	for (i=0; i<sizeof(k03); i++) {
		k03[i] = 0xaa;
	}
	printf("56be34521d144c88dbb8c733f0e8b3f6 (should be)\n");
	hmac_md5(d03, sizeof(d03), k03, sizeof(k03), digest);
	for (i = 0; i < 16; i++) {
		printf("%.2x", 0xFF & (unsigned int) digest[i]);
	}
	printf(" (was computed)\n\n");

	exit(0);
}
