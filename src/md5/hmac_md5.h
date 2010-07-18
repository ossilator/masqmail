void hmac_md5(
	unsigned char* text,   /* pointer to the message */
	int textlen,           /* length of the message */
	unsigned char* key,    /* pointer to the authentication key */
	int keylen,            /* length of the key */
	unsigned char* digest  /* pointer to allocated memory to store the computed HMAC */
);
