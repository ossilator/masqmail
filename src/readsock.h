// SPDX-FileCopyrightText: (C) 2000 Oliver Kurth
// SPDX-License-Identifier: GPL-2.0-or-later
/*
**  MasqMail
*/

#define READSOCKL_CHUG 0x01
#define READSOCKL_CVT_CRLF 0x02


int read_sockline(FILE *in, char *buf, int buf_len, int timeout, unsigned int flags);
int read_sockline1(FILE *in, char **pbuf, int *size, int timeout, unsigned int flags);
