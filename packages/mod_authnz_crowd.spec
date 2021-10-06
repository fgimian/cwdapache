Name:           mod_authnz_crowd
Version:        2.1
Release:        1%{?dist}
Summary:        Modules for integrating Apache httpd and Subversion with Atlassian Crowd

License:        Apache License, Version 2.0
URL:            https://confluence.atlassian.com/display/CROWD/Integrating+Crowd+with+Apache
Source0:        %{name}-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  autoconf automake curl-devel httpd-devel libtool libxml2-devel subversion-devel
Requires:       curl httpd-devel libtool libxml2 mod_dav_svn

Group:          System Environment/Daemons

%description
Modules for Apache httpd that allow Atlassian Crowd to be used for the authentication and authorisation of HTTP and Subversion requests

%prep
%setup -q

%build
libtoolize
autoreconf --install
%configure
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make
mkdir -p $RPM_BUILD_ROOT%{_libdir}/httpd/modules
%{_libdir}/httpd/build/instdso.sh SH_LIBTOOL='%{_libdir}/apr-1/build/libtool' src/mod_authnz_crowd.la $RPM_BUILD_ROOT%{_libdir}/httpd/modules
%{_libdir}/httpd/build/instdso.sh SH_LIBTOOL='%{_libdir}/apr-1/build/libtool' src/svn/mod_authz_svn_crowd.la $RPM_BUILD_ROOT%{_libdir}/httpd/modules
mv $RPM_BUILD_ROOT%{_libdir}/httpd/modules/mod_authnz_crowd.so.0.0.0 $RPM_BUILD_ROOT%{_libdir}/httpd/modules/mod_authnz_crowd.so
mv $RPM_BUILD_ROOT%{_libdir}/httpd/modules/mod_authz_svn_crowd.so.0.0.0 $RPM_BUILD_ROOT%{_libdir}/httpd/modules/mod_authz_svn_crowd.so
%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,-)
%attr(755,root,root) %{_libdir}/httpd/modules/mod_authnz_crowd.so
%attr(755,root,root) %{_libdir}/httpd/modules/mod_authz_svn_crowd.so
%doc LICENSE

%post
/usr/sbin/apxs -e -a -n authnz_crowd mod_authnz_crowd.so
cat << END > /tmp/httpd.conf.sed
/^[ \t]*[Ll][Oo][Aa][Dd][Mm][Oo][Dd][Uu][Ll][Ee][ \t]\+authz_svn_module[ \t]/ {
    s/^/# /
    a\
LoadModule authz_svn_crowd_module   modules/mod_authz_svn_crowd.so
}
END
sed -i.bak -f /tmp/httpd.conf.sed /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf
/usr/sbin/apachectl configtest
/usr/sbin/apachectl graceful || true

%preun
/usr/sbin/apxs -e -A -n authnz_crowd mod_authnz_crowd.so
cat << END > /tmp/httpd.conf.sed
/^[ \t]*[Ll][Oo][Aa][Dd][Mm][Oo][Dd][Uu][Ll][Ee][ \t]\+authz_svn_crowd_module[ \t]/ {
    s/^/# /
}
END
sed -i.bak -f /tmp/httpd.conf.sed /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf
/usr/sbin/apachectl configtest
/usr/sbin/apachectl graceful || true
