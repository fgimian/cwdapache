use 5.008000;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Atlassian::Crowd',
    VERSION_FROM      => 'lib/Atlassian/Crowd.pm', # finds $VERSION
    PREREQ_PM         => { Error => 0.1, SOAP::Lite => 0.69, version => 0.1 }, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      (ABSTRACT_FROM  => 'lib/Atlassian/Crowd.pm', # retrieve abstract from module
       ABSTRACT       => 'Perl interface to the Atlassian Crowd SOAP API',
       AUTHOR         => 'Atlassian') : ()),
);
