# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl Atlassian-Crowd.t'

#########################

# change 'tests => 1' to 'tests => last_test_to_print';

@tests = ();

sub loadTestPasswords {
	
	# In order to test the crowd SOAP calls we need to load a user-supplied 
	# config file with names, passwords and groups.
	open(INFILE, "t/testconfig.txt") or return 0;
	
	while (my $line = <INFILE>) {
		next if $line =~ /^#/;        # skip comments
		next if $line =~ /^\s*$/;     # skip empty lines	
		
		chomp $line;
		my @tokens = split /,/, $line;
		next if @tokens == 0 ;
		
		if((@tokens == 5)) {
			push @tokens, '';		# add an empty group token if not specified
		}
		
		if((@tokens == 6)) {
			push @tests, [ @tokens ];
		} else {
			chomp $line;
			diag("Bad test line [$line]");
			return 0;
		}		
	}
	
	# It's not an error to have no server tests.
	#return 0 if(@tests == 0);
	
	return 1;
}

use Test::More qw(no_plan);
BEGIN { 
	use_ok('Atlassian::Crowd');
};

# load password file
ok(loadTestPasswords(), 'Use the  t/testconfig.txt file to define tests');

# test svn path parsing -------------------------------------------------------

my $extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/!svn/wrk/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba/authztree/trunk/ls.txt');
is($extracted_path, 
	'/authztree/trunk/ls.txt', "extract_svnrepos_path[/svn/!svn/wrk/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba/authztree/trunk/ls.txt, $extracted_path]"); 
		
$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/!svn/act/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba');
is($extracted_path, 
	'', "extract_svnrepos_path[/svn/!svn/act/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/!svn/act/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba/');
is($extracted_path, 
	'', "extract_svnrepos_path[/svn/!svn/act/c82c7a9c-4fc4-4940-999a-4ce30ecbc2ba, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn/repos/', '/svn/repos/!svn/ver/25/authztree/branches/v2.0/vim.txt');
is($extracted_path, 
	'/authztree/branches/v2.0/vim.txt', "extract_svnrepos_path[/svn/repos/!svn/ver/25/authztree/branches/v2.0/vim.txt, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn/repos', '/svn/repos/!svn/ver/25/authztree/branches/v2.0/vim.txt');
is($extracted_path, 
	'/authztree/branches/v2.0/vim.txt', "extract_svnrepos_path[/svn/repos/!svn/ver/25/authztree/branches/v2.0/vim.txt, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/Atlassian-Crowd/trunk/lib/Atlassian');
is($extracted_path, 
	'/Atlassian-Crowd/trunk/lib/Atlassian', "extract_svnrepos_path[/svn/Atlassian-Crowd/trunk/lib/Atlassian, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/');
is($extracted_path, 
	'/', "extract_svnrepos_path[/, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn');
is($extracted_path, 
	'/', "extract_svnrepos_path[/svn, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/');
is($extracted_path, 
	'/', "extract_svnrepos_path[/svn/, $extracted_path]"); 

$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', '/svn/!svn/wrk/ca3a2965-4e23-4c24-b891-e415f64f74ce/authztree/branches/v1.1');
is($extracted_path, 
	'/authztree/branches/v1.1', "extract_svnrepos_path[/svn/!svn/wrk/ca3a2965-4e23-4c24-b891-e415f64f74ce/authztree/branches/v1.1, $extracted_path]"); 

#$extracted_path = Atlassian::Crowd::extract_svnrepos_path('/svn', 'http:/localhost/svn/authztree/branches/v2.0/v1.0_2');
#is($extracted_path, 
#	'/authztree/branches/v1.1', "extract_svnrepos_path[http:/localhost/svn/authztree/branches/v2.0/v1.0_2, $extracted_path]"); 


# SVN authz file parsing tests ------------------------------------------------

my %section_hash = Atlassian::Crowd::parse_svn_authz_file('t/test_authz.txt');

# Uncomment the following to get a printout of the file contents.
#for $section (keys %section_hash) {
#	diag("SECTION: $section");
#	for $user (keys %{$section_hash{$section}}) {
#		diag("   PARAM: $user = $section_hash{$section}{$user}");
#	}
#}

ok(%section_hash);

ok(defined $section_hash{'/'});
ok(defined $section_hash{'/crowdauth'});
ok(defined $section_hash{'/crowdauth/trunk'});
ok(defined $section_hash{'calc:/projects/calc'});
ok(defined $section_hash{'paint:/projects/paint'});
ok(defined $section_hash{'calc:/branches/calc/bug-142'});
ok(defined $section_hash{'calc:/branches/calc/bug-142/secret'});

ok(!defined $section_hash{'/chunkybacon'});
ok(!defined $section_hash{'groups'});

ok($section_hash{'paint:/projects/paint'}{'@paint-developers'} eq 'rw');
ok($section_hash{'paint:/projects/paint'}{'jane'} eq 'r');

ok(defined $section_hash{'calc:/branches/calc/bug-142/secret'}{'harry'});
ok($section_hash{'calc:/branches/calc/bug-142/secret'}{'harry'} eq '');

ok($section_hash{'/crowdauth'}{'*'} eq 'r');
is($section_hash{'/spaces'}{'@group with spaces'}, 'r', "Group with spaces in name");
is($section_hash{'/spaces'}{'@group with more spaces'}, '', "Group with spaces in name #2");
is($section_hash{'/spaces2'}{'@another group with spaces'}, 'rw', "Group with spaces in name #3");

my %no_section_hash = Atlassian::Crowd::parse_svn_authz_file('t/doesnt_exist.txt');
ok(scalar(keys(%no_section_hash)) == 0, "Empty hash");

# Authzfile tests -----------------------------------------------------------------

my @groups1 = ('grpone', 'grptwo');
my @groups2 = ('developers', 'administrators');

ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/branches/v1.0', 
		'andrewr', @groups1, 'r') == 1, 'evaluate_authz #1');

ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/branches/v1.0', 
		'darren', @groups2, 'w') == 1, 'evaluate_authz #2');

ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/banana', 
		'darren', @groups1, 'r') == 1, 'evaluate_authz #3');

ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/banana', 
		'darren', @groups1, 'w') == 0, 'evaluate_authz #4');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth', 
		'bogus', @groups1, 'r'), 1, 'evaluate_authz #5');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/trunk', 
		'bogus', @groups1, 'r'), 0, 'evaluate_authz #6');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/trunk/devel', 
		'bogus', @groups1, 'r'), 0, 'evaluate_authz #7');

# check recursive
ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/branches', 
		'andrewr', @groups1, 'rr') == 0, 'evaluate_authz #8');
ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth', 
		'andrewr', @groups1, 'wr') == 0, 'evaluate_authz #9');
ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/trunk', 
		'andrewr', @groups1, 'wr') == 0, 'evaluate_authz #10');
ok(Atlassian::Crowd::evaluate_authz(%section_hash, '/crowdauth/trunk/foo', 
		'andrewr', @groups1, 'wr') == 1, 'evaluate_authz #11');

# check root access
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/goomer/trunk', 
		'andrewr', @groups1, 'r'), 1, 'evaluate_authz #12');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/Atlassian-Crowd/trunk', 
		'andrewr', @groups1, 'w'), 1, 'evaluate_authz #12');

# check that we get the most permissive group (CWD-923)
my @groups3 = ('calc-developers', 'paint-developers');
my @groups4 = ('calc-developers', 'paint-developers');
my @groups5 = ('group with spaces');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup700', 
		'sally', @groups3, 'rw'), 1, 'evaluate_authz #13');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup700', 
		'sally', @groups4, 'rw'), 1, 'evaluate_authz #14');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup701', 
		'sally', @groups3, 'rw'), 1, 'evaluate_authz #15');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup701', 
		'sally', @groups4, 'rw'), 1, 'evaluate_authz #16');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup702', 
		'sally', @groups3, 'r'), 0, 'evaluate_authz #17');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/cwdsup702', 
		'sally', @groups4, 'r'), 0, 'evaluate_authz #18');

is(Atlassian::Crowd::evaluate_authz(%section_hash, '/spaces', 
		'derek', @groups5, 'r'), 1, 'evaluate_authz #19');
is(Atlassian::Crowd::evaluate_authz(%section_hash, '/spaces', 
		'derek', @groups5, 'rw'), 0, 'evaluate_authz #20');

# svn auth permission merging tests
is(Atlassian::Crowd::merge_access('n', 'rw'), 'rw', 'merge_access #1');
is(Atlassian::Crowd::merge_access('n', 'r'), 'r', 'merge_access #2');
is(Atlassian::Crowd::merge_access('n', 'd'), 'd', 'merge_access #3');
is(Atlassian::Crowd::merge_access('n', 'n'), 'n', 'merge_access #4');

is(Atlassian::Crowd::merge_access('r', 'n'), 'r', 'merge_access #5');
is(Atlassian::Crowd::merge_access('r', 'r'), 'r', 'merge_access #6');
is(Atlassian::Crowd::merge_access('r', 'rw'), 'rw', 'merge_access #7');
is(Atlassian::Crowd::merge_access('r', 'd'), 'r', 'merge_access #8');

is(Atlassian::Crowd::merge_access('rw', 'n'), 'rw', 'merge_access #9');
is(Atlassian::Crowd::merge_access('rw', 'r'), 'rw', 'merge_access #10');
is(Atlassian::Crowd::merge_access('rw', 'rw'), 'rw', 'merge_access #11');
is(Atlassian::Crowd::merge_access('rw', 'd'), 'rw', 'merge_access #12');

is(Atlassian::Crowd::merge_access('d', 'n'), 'd', 'merge_access #13');
is(Atlassian::Crowd::merge_access('d', 'r'), 'r', 'merge_access #14');
is(Atlassian::Crowd::merge_access('d', 'rw'), 'rw', 'merge_access #15');
is(Atlassian::Crowd::merge_access('d', 'd'), 'd', 'merge_access #16');


# Login tests -----------------------------------------------------------------

for $thetest (@tests) {
	my ($soapURL, $appName, $appPass, $userName, $userPass, $group) = @$thetest;
	#diag("--> $soapURL, $appName, $appPass, $userName, $userPass, $group");
	
	my $apptoken;
		
	# test failed app login
	$apptoken = Atlassian::Crowd::authenticate_app($soapURL, $appName, 'wrongpassword');
	ok(!defined $apptoken);
	
	# test successful app login
	$apptoken = Atlassian::Crowd::authenticate_app($soapURL, $appName, $appPass);
	ok(defined $apptoken);
	
	my $principaltoken;
	
	# test unsuccessful principal login
	$principaltoken = Atlassian::Crowd::authenticate_principal($soapURL, $appName, $apptoken, $userName, 'wrongpassword');
	ok(!defined $principaltoken);
	
	# test successful principal login
	$principaltoken = Atlassian::Crowd::authenticate_principal($soapURL, $appName, $apptoken, $userName, $userPass);
	ok(defined $principaltoken, "Principal login: [$userName], [$userPass]" );
	
	# Test checking group membership
	my $desiredGroupResult = 1;
	if($group =~ /^!(.+)$/) {
		$group = $1;
		$desiredGroupResult = 0;
	}
	
	next if $group eq '';
	
	is(Atlassian::Crowd::is_group_member($soapURL, $appName, $apptoken, $group, $userName), $desiredGroupResult, "Is Group Member [$userName, $group]");
	
	my @principal_groups = Atlassian::Crowd::find_group_memberships($soapURL, $appName, $apptoken, $userName);
	my $foundGroup = 0;
	foreach my $grp (@principal_groups) {
		if($grp eq $group) {
			$foundGroup = 1;
		}
	}
	if($desiredGroupResult == 1) {
		ok($foundGroup == 1, "group $group not found in list for $userName");
	} else {
		ok($foundGroup == 0, "group $group found in list for $userName");
	}
		
}

#########################


