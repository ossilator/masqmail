# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test.conf
	mkdir -p spool

test.conf: test.conf.tpl
	# fails if the current path contains `^'.
	sed "s/SMTP_HOST/`hostname`/; s^PWD^`pwd`^" $< >$@

clean:
	rm -f test.conf

realclean: clean
	rm -rf spool
	rm -f *.log $(LOGNAME)
