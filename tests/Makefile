# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test.conf local.sh smtpout.sh
	mkdir -p ./input ./lock

test.conf: conf.templ
	# fails if the current path contains `^'.
	sed "s/SMTP_HOST/`hostname`/; s^PWD^`pwd`^" conf.templ > test.conf

local.sh: test.templ
	sed s/RECV_HOST/localhost/ test.templ > local.sh
	chmod ugo+x local.sh

smtpout.sh: test.templ
	sed s/RECV_HOST/`hostname`/ test.templ > smtpout.sh
	chmod ugo+x smtpout.sh

clean:
	rm -f test.conf local.sh smtpout.sh
	rm -rf ./input ./lock
