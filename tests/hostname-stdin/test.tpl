#!/bin/sh

# path to the masqmail executable
mm_bin=../../src/masqmail

hfrom="\"Fritz Meier\" <`logname`@RECV_HOST>"
hto="$hfrom"
to=`logname`@RECV_HOST
hsubject="Masqmail test: `basename pwd`"


# Testing with rcpt on cmd line
# (dot does end)
#
# the command to be run:
cmd="$mm_bin -C ./test.conf $to"

$cmd <<EOF
From: $hfrom
To: $hto
Subject: $hsubject

Hallo Fritz!
..
there is a dot above (Yes, one and not two).

command was: $cmd

Fritz
.

EOF


# Testing with rcpt on cmd line with -oi option
# (dot does not end)
#
# the command to be run:
cmd="$mm_bin -C ./test.conf -oi $to"

$cmd <<EOF
From: $hfrom
To: $hto
Subject: $hsubject

Hallo Fritz!
.
there is a dot above.

command was: $cmd

Fritz

EOF


# Testing with rcpt read from headers (-t option)
# (dot does end)
#
# the command to be run:
cmd="$mm_bin -C ./test.conf -t"

$cmd <<EOF
From: $hfrom
To: $hto
Subject: $hsubject

Hallo Fritz!
..
there is a dot above.

command was: $cmd

Fritz
.

EOF
