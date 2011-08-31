# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test test.conf
	mkdir -p ./input ./lock

test.conf: test.conf.tpl
	# fails if the current path contains `^'.
	sed "s/SMTP_HOST/`hostname`/; s^PWD^`pwd`^" $< >$@

test: test.tpl
	sed s/RECV_HOST/`hostname`/ $< >$@
	chmod +x $@

clean:
	rm -f test.conf test

realclean: clean
	rm -rf ./input ./lock
	rm -f *.log $(LOGNAME)
