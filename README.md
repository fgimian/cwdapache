# Apache Connector for Crowd

See [Integrating Crowd with Apache](https://confluence.atlassian.com/x/rgGY) for background information and usage instructions.

# About

This project is a fork of [Atlassian's Apache Connector for Crowd](https://bitbucket.org/atlassian/cwdapache) with the following changes:

* [Mathias Burger's Apache 2.4 compatibility patch](https://bitbucket.org/atlassian/cwdapache/pull-request/18/added-apache-24-compatibility-and-fixed/diff) has been applied.
* I have written the necessary files to allow for packaging of this for Debian-based distributions. This has currently only been successfully tested against Ubuntu 14.04 (trusty).

# Issues

Sadly, [Atlassian have dropped support](https://confluence.atlassian.com/display/CROWD/Integrating+Crowd+with+Subversion) for this module.  I'm not an experienced C coder myself, but I'd be happy to accept pull requests which are approved by various parties and integrate them into future verisons.

# Building

The following instructions assume your current working directory is the directory where cwdapache is checked out, and that [Git](http://git-scm.com/) is available on the build machine (it's used during the build):

     git clone https://github.com/fgimian/cwdapache.git
     cd cwdapache

## Building on CentOS 6

Last tested on CentOS 6.5:

    yum install autoconf automake curl-devel httpd-devel libtool libxml2-devel subversion-devel curl httpd-devel libtool libxml2 mod_dav_svn
    libtoolize
    autoreconf --install
    ./configure
    make

### Optional: How to Build an RPM

If you'd like to build an RPM for later installation:

    yum install rpm-build
    echo "%_topdir $HOME/rpmbuild" > ~/.rpmmacros
    mkdir -p ~/rpmbuild/{SOURCES,BUILD,SRPMS,RPMS}
    rm mod_authnz_crowd-*.tar.gz
    make dist # builds source distribution which is used as the source for the RPM
    cp mod_authnz_crowd-*.tar.gz ~/rpmbuild/SOURCES
    sed "s/Version:        .*/Version:        $(./version-gen)/" packages/mod_authnz_crowd.spec > packages/mod_authnz_crowd-current.spec
    rpmbuild -ba --target x86_64 packages/mod_authnz_crowd-current.spec # or '--target x86' for a 32 bit build
    rm packages/mod_authnz_crowd-current.spec
    echo "Your RPMS should be in..." && ls -R ~/rpmbuild/SRPMS ~/rpmbuild/RPMS

## Building on CentOS 5

Last tested on CentOS 5.10.

Follow the instructions for CentOS 6, but:

- you must use a more recent version of [libtool](http://www.gnu.org/software/libtool/libtool.html). [libtool 2.2.6b](http://mirror.aarnet.edu.au/pub/gnu/libtool/libtool-2.2.6b.tar.gz) is what CentOS 6 ships with at time of writing, and is known to work.

## Building on Ubuntu 14.04 (trusty) or Debian 6 (squeeze):

    aclocal
    libtoolize
    autoheader
    automake --force-missing --add-missing
    autoreconf
    ./configure
    make

### Optional: How to Build a Debian package for Ubuntu 14.04 (trusty)

If you'd like to build a Debian for later installation:

    sudo apt-get install devscripts equivs
    sudo mk-build-deps -i -r
    dpkg-buildpackage -us -us
    echo "Your Debian package should be in..." && ls ../libapache2-mod-auth-crowd_*.deb

# Installing

    make install

# After installing

Apache config example

    <Directory /var/www/htdocs/>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride None
        Order allow,deny
        allow from all

        AuthName "__AUTHNAME__"
        AuthType Basic
        AuthBasicProvider crowd

        CrowdAppName __APPNAME__
        CrowdAppPassword __APPPWD__
        CrowdURL https://__CROWDSERVER__/crowd/
        CrowdCertPath __CERTPATH__

        CrowdAcceptSSO On
        CrowdCreateSSO On

        Require valid-user
        #configure groups in apache 2.4 as follows:
        #Require crowd-group __GROUP__
    </Directory>

Modify apache config, do NOT USE .htaccess!

    service apache2 reload
