REM Batch file to Build the ActivePerl PPD package.
perl Makefile.PL
nmake
"c:\Program Files\GnuWin32\bin\tar.exe" cvf Apache-CrowdAuth.tar blib
"c:\Program Files\GnuWin32\bin\gzip.exe" --best Apache-CrowdAuth.tar
nmake ppd
@echo Now edit Apache-CrowdAuth.ppd and change the CODEBASE element
@echo To point to where you are going to put the tar.gz file 

