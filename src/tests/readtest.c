#include "masqmail.h"
#include "readsock.h"

int
main(void)
{
	char *buf = g_malloc(20);
	int size = 20, ret;

	ret = read_sockline1(stdin, &buf, &size, 60, READSOCKL_CVT_CRLF);
	/*  ret = read_sockline(stdin, buf, size, 60, READSOCKL_CHUG); */

	printf("%s\n", buf);
	printf("ret = %d, size = %d, strlen = %d\n", ret, size, (int) strlen(buf));

	return 0;
}
