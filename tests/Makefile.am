test.conf: conf.templ
	sed s/SMTP_HOST/`hostname`/ conf.templ > test.conf

local.sh: test.templ
	sed s/RECV_HOST/localhost/ test.templ > local.sh
	chmod ugo+x local.sh

smtpout.sh: test.templ
	sed s/RECV_HOST/`hostname`/ test.templ > smtpout.sh
	chmod ugo+x smtpout.sh

input/:
	mkdir input

all: test.conf local.sh smtpout.sh input/

EXTRA_DIST=conf.templ test.templ

conf.templ:
test.templ:
