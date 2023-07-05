test.conf: $(srcdir)/conf.templ
	sed s/SMTP_HOST/`hostname`/ $(srcdir)/conf.templ > test.conf

local.sh: $(srcdir)/test.templ
	sed s/RECV_HOST/localhost/ $(srcdir)/test.templ > local.sh
	chmod ugo+x local.sh

smtpout.sh: $(srcdir)/test.templ
	sed s/RECV_HOST/`hostname`/ $(srcdir)/test.templ > smtpout.sh
	chmod ugo+x smtpout.sh

input/:
	mkdir input

all: test.conf local.sh smtpout.sh input/

EXTRA_DIST=conf.templ test.templ

conf.templ:
test.templ:
