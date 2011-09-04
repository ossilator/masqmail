# Makefile by markus schnalke <meillo@marmaro.de>
# heavily based on Makefile.am written by oliver kurth

all: test test.conf test.route
	mkdir -p ./input ./lock

test.conf: test.conf.tpl
	# fails if the current path contains `^'.
	sed "s^PWD^`pwd`^" $< >$@

test: test.tpl
	sed s/RECV_HOST/`hostname`/ $< >$@
	chmod +x $@

test.route:
	echo mail_host=\"`hostname`\" >$@
	echo "resolve_list = byname" >>$@

clean:
	rm -f test.conf test test.route

realclean: clean
	rm -rf ./input ./lock
	rm -f *.log
