# Installation Notes for Debian 6.0:

Clone repository, compile and install.

    cd /tmp
    git clone https://bitbucket.org/atlassian/cwdapache.git
    cd cwdapache
    aclocal
    libtoolize
    automake --force-missing --add-missing
    autoreconf
    ./configure
    make 
    make install

Modify apache config, do NOT USE .htaccess!

    service apache2 reload
