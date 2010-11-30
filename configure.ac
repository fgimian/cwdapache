AC_INIT([mod_authnz_crowd], [2.0], [support@atlassian.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_PROG_CC
AC_PROG_LIBTOOL
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([
    Makefile
    src/Makefile
    src/svn/Makefile
])
AC_CONFIG_MACRO_DIR([m4])

AC_CHECK_FILE([/usr/local/apache2/include/httpd.h], [APACHE_INCLUDE_DIR="/usr/local/apache2/include"], [
    AC_CHECK_FILE([/usr/include/httpd/httpd.h], [APACHE_INCLUDE_DIR="/usr/include/httpd"], [
        AC_MSG_ERROR([Could not locate Apache include directory])
    ])
])
AC_SUBST([APACHE_INCLUDE_DIR])

AC_PATH_PROG([HTTPD], [httpd], , [/usr/local/apache2/bin:/usr/sbin])
APACHE_BIN_DIR=`AS_DIRNAME($HTTPD)`
AC_SUBST([APACHE_BIN_DIR])

AC_CHECK_FILE([/usr/local/include/subversion-1/svn_client.h], [SVN_DIR="/usr/local"], [
    AC_CHECK_FILE([/usr/include/subversion-1/svn_client.h], [SVN_DIR="/usr"], [
        AC_MSG_ERROR([Could not locate Subversion directory])
    ])
])
AC_SUBST([SVN_DIR])

AC_CHECK_FILE([/usr/libexec/apache2/mod_dav.so], [APACHE_MODULES_DIR="/usr/libexec/apache2"], [
    AC_CHECK_FILE([/usr/lib64/httpd/modules/mod_dav.so], [APACHE_MODULES_DIR="/usr/lib64/httpd/modules"], [
        AC_CHECK_FILE([/usr/lib/httpd/modules/mod_dav.so], [APACHE_MODULES_DIR="/usr/lib/httpd/modules"], [
            AC_MSG_ERROR([Could not locate Apache modules directory])
        ])
    ])
])
AC_SUBST([APACHE_MODULES_DIR])

AC_CHECK_FILE([/usr/local/apache2/conf/httpd.conf], [HTTPD_CONF="/usr/local/apache2/conf/httpd.conf"], [
    AC_CHECK_FILE([/etc/httpd/conf/httpd.conf], [HTTPD_CONF="/etc/httpd/conf/httpd.conf"], [
        AC_MSG_ERROR([Could not locate Apache configuration file])
    ])
])
AC_SUBST([HTTPD_CONF])

AC_CHECK_FILE([/usr/local/apache2/bin/apxs], [HTTPD_BIN_DIR="/usr/local/apache2/bin"], [
    AC_CHECK_FILE([/usr/sbin/apxs], [HTTPD_BIN_DIR="/usr/sbin"], [
        AC_MSG_ERROR([Could not locate Apache binaries directory])
    ])
])
AC_SUBST([HTTPD_BIN_DIR])

AC_OUTPUT