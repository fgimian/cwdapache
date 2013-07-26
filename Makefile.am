ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = LICENSE version-gen
SUBDIRS = src

dist-hook:
	find $(distdir)
	rm -r $(distdir)/aclocal.m4 $(distdir)/config.guess $(distdir)/config.h.in $(distdir)/configure $(distdir)/config.sub $(distdir)/depcomp $(distdir)/install-sh $(distdir)/ltmain.sh $(distdir)/Makefile.in $(distdir)/missing $(distdir)/m4/* $(distdir)/src/Makefile.in $(distdir)/src/svn/Makefile.in
	./version-gen >$(distdir)/dist-version
