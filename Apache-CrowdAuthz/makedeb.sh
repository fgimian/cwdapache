#!/bin/sh
/bin/rm -rf ./debian
make clean
dh-make-perl --email=support@atlassian.com
debuild -us -uc
