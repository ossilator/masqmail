SUBDIRS=man xml

man: man/masqmail.8 man/mservdetect.8 man/masqmail.conf.5 man/masqmail.route.5 man/masqmail.get.5 man/masqmail.aliases.5

html: html/masqmail.8.html html/mservdetect.8.html html/masqmail.conf.5.html html/masqmail.route.5.html html/masqmail.get.5.html html/masqmail.aliases.5.html

man/masqmail.8:	xml/masqmail.8.xml
	xmltoman $< >$@

man/mservdetect.8:	xml/mservdetect.8.xml
	xmltoman $< >$@

man/masqmail.conf.5:	xml/masqmail.conf.5.xml
	xmltoman $< >$@

man/masqmail.route.5:	xml/masqmail.route.5.xml
	xmltoman $< >$@

man/masqmail.get.5:	xml/masqmail.get.5.xml
	xmltoman $< >$@

man/masqmail.aliases.5:	xml/masqmail.aliases.5.xml
	xmltoman $< >$@


html/masqmail.8.html:	xml/masqmail.8.xml
	xmlmantohtml $< >$@

html/mservdetect.8.html:	xml/mservdetect.8.xml
	xmlmantohtml $< >$@

html/masqmail.conf.5.html:	xml/masqmail.conf.5.xml
	xmlmantohtml $< >$@

html/masqmail.route.5.html:	xml/masqmail.route.5.xml
	xmlmantohtml $< >$@

html/masqmail.get.5.html:	xml/masqmail.get.5.xml
	xmlmantohtml $< >$@

html/masqmail.aliases.5.html:	xml/masqmail.aliases.5.xml
	xmlmantohtml $< >$@

#clean:
#	rm -f man/*.[58]
#	rm -r html/*.html
