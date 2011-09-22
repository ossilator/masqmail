/*
hmac_md5 -- implements RFC 2104

Copyright 2010, markus schnalke <meillo@marmaro.de>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.


My motivation to write this code was the lack of a nicely licensed
hmac_md5 function in C. I programmed it following the RFC's text.
Obviously this code is highly similar to the sample code of the RFC.
The code is tested against the test vectors of the RFC. Wikipedia's
HMAC page helped me to understand the algorithm better.

This hmac_md5 function requires an OpenSSL-compatible MD5
implementation. There are Public Domain MD5 implementations by Colin
Plumb and by Solar Designer. You probably want to use one of these.
*/

#include <string.h>
#include "md5.h"


const int blocksize = 64;
const int hashsize = 16;


/*
The computed HMAC will be written to `digest'.
Ensure digest points to hashsize bytes of allocated memory.
*/
void
hmac_md5(unsigned char *text, int textlen, unsigned char *key, int keylen, unsigned char *digest)
{
	int i;
	MD5_CTX context;
	unsigned char ipad[blocksize];
	unsigned char opad[blocksize];

	/* too long keys are replaced by their hash value */
	if (keylen > blocksize) {
		MD5_Init(&context);
		MD5_Update(&context, key, keylen);
		MD5_Final(digest, &context);
		key = digest;
		keylen = hashsize;
	}

        /* copy the key into the pads */
	memset(ipad, 0, sizeof(ipad));
	memcpy(ipad, key, keylen);

	memset(opad, 0, sizeof(opad));
	memcpy(opad, key, keylen);

        /* xor the pads with their ``basic'' value */
	for (i=0; i<blocksize; i++) {
		ipad[i] ^= 0x36;
		opad[i] ^= 0x5c;
	}

	/* inner pass (ipad ++ message) */
	MD5_Init(&context);
	MD5_Update(&context, ipad, sizeof(ipad));
	MD5_Update(&context, text, textlen);
	MD5_Final(digest, &context);

	/* outer pass (opad ++ result of inner pass) */
	MD5_Init(&context);
	MD5_Update(&context, opad, sizeof(opad));
	MD5_Update(&context, digest, hashsize);
	MD5_Final(digest, &context);
}
