fix_man = \
	masqmail.aliases.5

in_man = \
	masqmail.8.in \
	mservdetect.1.in \
	masqmail.conf.5.in \
	masqmail.route.5.in \
	rmail.8.in

# don't forget to update AC_CONFIG_FILES in configure.ac!
out_man = \
	masqmail.8 \
	mservdetect.1 \
	masqmail.conf.5 \
	masqmail.route.5 \
	rmail.8

man_MANS = $(fix_man) $(out_man)

EXTRA_DIST = $(fix_man) $(in_man)

update-dates:
	@top_srcdir@/devel/update-manpage-date @VERSION@ $(EXTRA_DIST)
