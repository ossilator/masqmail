
all:
	cd hostname-stdin && make
	cd localhost-stdin && make
	cd relay-to-localhost-mta && make
	cd relay-to-hostname-mta && make

run: all
	cd hostname-stdin && ./test
	cd localhost-stdin && ./test
	cd relay-to-localhost-mta && ./test
	cd relay-to-hostname-mta && ./test

clean:
	cd hostname-stdin && make clean
	cd localhost-stdin && make clean
	cd relay-to-localhost-mta && make clean
	cd relay-to-hostname-mta && make clean

realclean:
	cd hostname-stdin && make realclean
	cd localhost-stdin && make realclean
	cd relay-to-localhost-mta && make realclean
	cd relay-to-hostname-mta && make realclean
