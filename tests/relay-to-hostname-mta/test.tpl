#!/bin/sh

# path to the masqmail executable
mm_bin=../../src/masqmail

hfrom="\"Fritz Meier\" <$LOGNAME@RECV_HOST>"
hto="$hfrom"
to=$LOGNAME@RECV_HOST
hsubject="Masqmail test: relay-to-hostname-mta"


# the command to be run:
cmd="$mm_bin -C ./test.conf $to"

$cmd <<EOF
From: $hfrom
To: $hto
Subject: $hsubject

Hallo Fritz!

command was: $cmd

Fritz
.

EOF
