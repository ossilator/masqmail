# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test.conf local.sh smtpout.sh


test.conf: conf.templ
	sed s/SMTP_HOST/`hostname`/ conf.templ > test.conf

local.sh: test.templ
	sed s/RECV_HOST/localhost/ test.templ > local.sh
	chmod ugo+x local.sh

smtpout.sh: test.templ
	sed s/RECV_HOST/`hostname`/ test.templ > smtpout.sh
	chmod ugo+x smtpout.sh

clean:
	rm -f test.conf local.sh smtpout.sh
