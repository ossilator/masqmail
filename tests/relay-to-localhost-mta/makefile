# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test test.conf
	mkdir -p spool

test.conf: test.conf.tpl
	# fails if the current path contains `^'.
	sed "s^PWD^`pwd`^" $< >$@

test: test.tpl
	sed s/RECV_HOST/`hostname`/ $< >$@
	chmod +x $@

clean:
	rm -f test.conf test

realclean: clean
	rm -rf spool
	rm -f *.log
