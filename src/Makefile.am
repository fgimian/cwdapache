AUTOMAKE_OPTIONS = -Wno-override
SUBDIRS = svn
lib_LTLIBRARIES = mod_authnz_crowd.la
mod_authnz_crowd_la_SOURCES = mod_authnz_crowd.c mod_authnz_crowd.h crowd_client.c crowd_client.h cache.c cache.h util.c util.h
mod_authnz_crowd_la_LDFLAGS = -module -lcurl `xml2-config --libs`
mod_authnz_crowd_la_CFLAGS = -g -Wmissing-prototypes -O1
AM_CFLAGS = `apr-1-config --cflags`
AM_CPPFLAGS = -I@APACHE_INCLUDE_DIR@ `apr-1-config --cppflags --includes` `xml2-config --cflags`
TESTS = test.py
TESTS_ENVIRONMENT = APACHE_BIN_DIR=@APACHE_BIN_DIR@

test.py : httpd/conf/common.conf httpd/conf/httpd_svn.conf

httpd/conf/common.conf : httpd/conf/common.conf.in
	APACHE_MODULES_DIR=@APACHE_MODULES_DIR@ CURDIR=$(CURDIR) envsubst < httpd/conf/common.conf.in > httpd/conf/common.conf

httpd/conf/httpd_svn.conf : httpd/conf/httpd_svn.conf.in
	APACHE_MODULES_DIR=@APACHE_MODULES_DIR@ CURDIR=$(CURDIR) envsubst < httpd/conf/httpd_svn.conf.in > httpd/conf/httpd_svn.conf

install:
	cp @HTTPD_CONF@ /tmp/httpd.conf.bak
	@APXS@ -i -a mod_authnz_crowd.la
	@APXS@ -e -a -n dav_svn modules/mod_dav_svn.so
	@APXS@ -i -a svn/mod_authz_svn_crowd.la
	if [ -e /etc/apache2/mods-enabled/dav.load ]; then mv /etc/apache2/mods-enabled/dav.load /etc/apache2/mods-enabled/1dav.load; fi
	if [ -e /etc/apache2/mods-enabled/dav_svn.load ]; then mv /etc/apache2/mods-enabled/dav_svn.load /etc/apache2/mods-enabled/1dav_svn.load; fi
	@APACHECTL@ configtest || mv /tmp/httpd.conf.bak @HTTPD_CONF@
	@APACHECTL@ graceful
