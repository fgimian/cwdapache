package Atlassian::Crowd;

use 5.008000;
use strict;
use warnings;

require Exporter;

# Uncomment the following line (and comment out the line below it) to
# enable debug output of the SOAP messages.
# use SOAP::Lite +trace => qw (debug);
use SOAP::Lite;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Atlassian::Crowd ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '1.3';


# Namespace
my $NS = "urn:SecurityServer";

# namespace attribute used in SOAP call creation.
my $XMLNS = 'http://authentication.integration.crowd.atlassian.com';

# Preloaded methods go here.

# ---------------------------------------------------------------------------

sub make_soap_call {
	my ($serverURL, $method, @params) = @_;
	
	my $search = SOAP::Lite
		->readable(1)
		->xmlschema('http://www.w3.org/2001/XMLSchema')
		->on_action( sub { return '""';} )
		->proxy($serverURL)
		->uri($NS)
		->default_ns($XMLNS);
	
	my $app_method = SOAP::Data->name($method)
		->uri($NS);
	
	my $som = $search->call($app_method => @params);
	
	return $som;
}

# ---------------------------------------------------------------------------

# Authenticate the application
sub authenticate_app {
	my ($serverURL, $app_name, $app_credential) = @_;
	#my $rlog = $r->log;
	
	if(!defined($app_name) || !defined($app_credential)) {
		return undef;
	}
	
	my @app_params = (
	SOAP::Data->name('in0' =>
		\SOAP::Data->value(
			SOAP::Data->name('credential' => \SOAP::Data->value(
				SOAP::Data->name('credential' => $app_credential)->type('string')))->attr({xmlns => $XMLNS}),
				SOAP::Data->name('name' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
				SOAP::Data->name('validationFactors' => undef)->attr({xmlns => $XMLNS})
	)));
	
	my $app_som = make_soap_call($serverURL, 'authenticateApplication', @app_params);
	
	if (!defined($app_som)) {
		return undef;
	} elsif ($app_som->fault) {
		return undef;
	}
	
	# get the token
	my $appToken = $app_som->valueof('//token');
	
	if(!defined($appToken)) {
		return undef;
	}
		
	return $appToken;
}

# ---------------------------------------------------------------------------

# authenticate a principal. Returns a principal token on successfull login, and
# undef on failure.
sub authenticate_principal {
	
	my ($serverURL, $app_name, $appToken, $principal_name, $principal_credential) = @_;
	
	if(!defined($appToken)) {
		return undef;
	}
	
	my $principal_method = SOAP::Data->name('authenticatePrincipal')
	->uri($NS);
	
	my @principal_params = (
	SOAP::Data->name('in0' =>
		\SOAP::Data->value(
				SOAP::Data->name('name' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
				SOAP::Data->name('token' => $appToken)->attr({xmlns => $XMLNS}),
	)),
	SOAP::Data->name('in1' =>
	\SOAP::Data->value(
		SOAP::Data->name('application' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
		SOAP::Data->name('credential' => \SOAP::Data->value(
			SOAP::Data->name('credential' => $principal_credential)->type('string')))->attr({xmlns => $XMLNS}),
			SOAP::Data->name('name' => $principal_name)->type('string')->attr({xmlns => $XMLNS}),
			SOAP::Data->name('validationFactors' => undef)->attr({xmlns => $XMLNS})
			))
	);
	
	my $principal_som = make_soap_call($serverURL, 'authenticatePrincipal', @principal_params);
	
	if (!defined($principal_som)) {
		return undef;
	} elsif ($principal_som->fault) { # will be defined if Fault element is in the message
		return undef;
	} else {
		my $principalToken = $principal_som->valueof('//authenticatePrincipalResponse/out');

		if(defined($principalToken)) {
			return $principalToken;
		} else {
			return undef;
		}
	}
	return undef;
}

# ---------------------------------------------------------------------------

sub find_group_memberships($$$$) {
	my ($serverURL, $app_name, $appToken, $principal_name) = @_;
	if(!defined($appToken)) {
		return ();
	}
	
	my $findgroupmemberships_method = SOAP::Data->name('findGroupMemberships')->uri($NS);
	
	my @findgroupmemberships_params = (
		SOAP::Data->name('in0' => 
			\SOAP::Data->value(
					SOAP::Data->name('name' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
					SOAP::Data->name('token' => $appToken)->attr({xmlns => $XMLNS}),
		)),
		SOAP::Data->name('in1' => $principal_name)->type('string')->attr({xmlns => $XMLNS})
	);
	
	my $findgroupmemberships_som = make_soap_call($serverURL, 'findGroupMemberships', @findgroupmemberships_params);
	
	if (!defined($findgroupmemberships_som)) {
		return undef;
	} elsif ($findgroupmemberships_som->fault) { # will be defined if Fault element is in the message
		return undef;
	} else {
		# return value should be an array of strings.
		my $groupMembership = $findgroupmemberships_som->valueof('//findGroupMembershipsResponse/out');

		if(ref($groupMembership) eq "HASH") {
			if(exists $groupMembership->{'string'}) {
				my $strings = $groupMembership->{'string'};
				if(!ref($strings)) {
					# if it's not a reference to an array, then its a string
					# Test::More::diag("\n--> STRING $strings");
					return (scalar($strings));
				} elsif(ref($strings) eq 'ARRAY') {
					my @retarr = @$strings;
					return @retarr;
				}
			} else {
				return ();
			}
		} else {
			return ();
		}
	}
	return ();
}

# ---------------------------------------------------------------------------

# Check group membership for a principal. Requires an authenticated app token.
# Returns 1 if principal is a member, 0 otherwise 
sub is_group_member($$$$$) {
	
	my ($serverURL, $app_name, $appToken, $group_name, $principal_name) = @_;
	if(!defined($appToken)) {
		return undef;
	}
	
	my $isgroupmember_method = SOAP::Data->name('isGroupMember')->uri($NS);
	
	my @isgroupmember_params = (
		SOAP::Data->name('in0' => 
			\SOAP::Data->value(
					SOAP::Data->name('name' => $app_name)->type('string')->attr({xmlns => $XMLNS}),
					SOAP::Data->name('token' => $appToken)->attr({xmlns => $XMLNS}),
		)),
		SOAP::Data->name('in1' => $group_name)->type('string')->attr({xmlns => $XMLNS}),
		SOAP::Data->name('in2' => $principal_name)->type('string')->attr({xmlns => $XMLNS})	
	);
	
	my $isgroupmember_som = make_soap_call($serverURL, 'isGroupMember', @isgroupmember_params);
	
	if (!defined($isgroupmember_som)) {
		return 0;
	} elsif ($isgroupmember_som->fault) { # will be defined if Fault element is in the message
		return 0;
	} else {
		my $groupMembership = $isgroupmember_som->valueof('//isGroupMemberResponse/out');

		if(defined($groupMembership)) {
			if($groupMembership eq 'true') {
				return 1;
			} else {
				return 0;
			}
		} else {
			return 0;
		}
	}
	return 0;
}

# ---------------------------------------------------------------------------

# Extract the repository part of an uri passed through the svn DAV 
# interface
sub extract_svnrepos_path($$) {
	my ($location, $uri) = @_;
	
	my $repos_path = $uri;
	
	# first, strip off the location
	$repos_path =~ s/^$location//;
	
	# now we need to look for (and remove) the 'special' SVN url fragment: 
	# '!svn' that svn uses to indicate operations.
	
	$repos_path =~ s/^\/!svn/!svn/;	# strip leading slash
	
	if($repos_path =~ /!svn/) {
		
		if($repos_path =~ /!svn\/ver\//) {
			$repos_path =~ s/!svn\/ver\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/his\//) {
			$repos_path =~ s/!svn\/his\///;
		}
		if($repos_path =~ /!svn\/wrk\//) {
			$repos_path =~ s/!svn\/wrk\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/act\//) {
			$repos_path =~ s/!svn\/act\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/vcc\//) {
			$repos_path =~ s/!svn\/vcc\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/bc\//) {
			$repos_path =~ s/!svn\/bc\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/bln\//) {
			$repos_path =~ s/!svn\/bln\/\S+?(\/|$)//;
		}
		if($repos_path =~ /!svn\/wbl\//) {
			$repos_path =~ s/!svn\/wbl\/\S+?\/\S+?(\/|$)//;
		}
	} else {
		# if this isn't a '!svn' url, then restore a leading slash if the
		# string is empty (ie: we're at the repository root)
		if($repos_path eq '') {
			$repos_path = '/';
		}
	}
	
	# collapse adjacent slashes if we have any
	$repos_path =~ s/\/\/+/\//g;
	
	# if the path doesn't start with a slash, add one
	if(($repos_path ne '') and ($repos_path !~ /^\//)) {
		$repos_path = '/'.$repos_path;
	}
		
	return $repos_path;
}

# ---------------------------------------------------------------------------

# Trim function to remove whitespace from the start and end of the string
sub trim($)
{
	my $string = shift;
	$string =~ s/^\s+//;
	$string =~ s/\s+$//;
	return $string;
}

# ---------------------------------------------------------------------------
# parse the SVN auth file. Return a hash of paths to user and group access
sub parse_svn_authz_file($) {
	
	my ($filename) = @_;
	
	my %section_hash = ();
	
	open(INFILE, $filename) or return %section_hash;
	
	my $in_section = 0;
	my $section_name = '';
	
	while (my $line = <INFILE>) {
		next if $line =~ /^#/;        # skip comments
		next if $line =~ /^\s*$/;     # skip empty lines
		
		if ($line =~ /^\s*\[(\S+)\]\s*$/) {
			$in_section = 1;
			$section_name = $1;
			
			if($section_name ne 'groups') {
				$section_hash{$section_name} = {};
			}
			next;
		}
	
		if ($line =~ /^\[/) {
			$in_section = 0;
			next;
		}
		
		# skip the 'groups' section
		
		if (($section_name ne 'groups') and $in_section and $line =~ /^(.+)=(.*)$/) {
			my $param = trim($1);
			my $value = trim($2);
			
			$section_hash{$section_name}{$param} = $value;
			print "$section_name : [$param] = [$value]\n";
		}
	}

	close(INFILE);	
	
	return %section_hash;
}


# ---------------------------------------------------------------------------

# Evaluate whether a particular user should be granted access to $repos_path
# Returns 1 if access should be granted, 0 otherwise.
#
# %section_hash is a hash returned by using parse_svn_authz_file() 
# $repos_path is the repository path to check
# $user is the user name
# @groups is the list of groups the user belongs to
# $access is the type of access required: 
#        "r": read access
#        "w": write access
#       "rr": read recursive (checks all subdirectories of $repos_path too)
#       "wr": write recursive (checks all subdirectories of $repos_path too)
#
sub evaluate_authz(\%$$\@$) {
	my ($section_hash, $repos_path, $user, $groups, $access) = @_;
	
	my $access_specified = '';
	my $access_granted = 0;
	my $working_path = $repos_path;
	
	if($access eq "rw") {
		$access = "wr";
	}
	
	if($working_path eq '') {
		# special case, an empty path indicates a special SVN command uri
		# (eaten in extract_svnrepos_path) that should always be allowed
		return 1;
	}
	
	# add a leading slash if it doesn't have one.
	if($working_path !~ /^\//) {
		$working_path = '/'.$working_path;
	}
	
	PATH: while($working_path ne '') {
		$access_specified = evaluate_single_path_authz($section_hash, $working_path, $user, $groups);
		
		#Test::More::diag("WORKING_PATH: $working_path -> $access_specified");
		if($access_specified ne 'n') {
			last PATH;
		}
				
		if($working_path eq '/') {
			$working_path = '';   # if we've processed the root we're done.
		} else {
			# chop the last element off the end and continue
			$working_path =~ s/\/[^\/]*$//;
			if($working_path eq '') {
				$working_path = '/';  # make sure we try the root.
			}
		}
		
	}
	
	#Test::More::diag("access_specified = $access_specified");
	if($access_specified eq 'r') {
		# We've got read access allowed, which is ok unless we wanted write
		if($access eq 'w' or $access eq 'wr') {
			$access_granted = 0;
		} else {
			$access_granted = 1;
		}
	} elsif($access_specified eq 'rw') {
		$access_granted = 1;  # read or write access requested and granted
	} else {
		$access_granted = 0;  # no perms found for the user
	}
	
	# if we've granted access, do the recursion check
	if($access_granted) {
		if($access eq 'rr' or $access eq 'wr') {
			# what we need to do is check the _entire_ path list for subpaths
			# that the user doesn't have access to and decline access if there
			# are any.
			foreach my $path (keys %$section_hash) {
				#Test::More::diag("RECURSION: Checking $path...");
				if($path =~ /^\Q$repos_path\E.+/) {
					#Test::More::diag("CHECKING:     $path is a subpath of $repos_path...");
					my $path_access = evaluate_single_path_authz($section_hash, $path, $user, $groups);
					if ($path_access eq 'd') {
						# user is denied access to a subpath
						$access_granted = 0;
						#Test::More::diag("DENIED(u):     $path is a subpath of $repos_path...");
						last;
					} elsif (($access eq 'wr') and ($path_access eq 'r')) {
						# user is denied write access to a subpath
						$access_granted = 0;
						#Test::More::diag("DENIED(w):     $path is a subpath of $repos_path...");
						last;
					}					
				}
			}
		}
	}
	
	#Test::More::diag("access_granted = $access_granted");
	return $access_granted;
}

# ---------------------------------------------------------------------------

# 'merge' a new access with a current one in such a way that the most
# permissive access is returned
sub merge_access($$) {
	my ($orig_access, $new_access) = @_;
	if(($orig_access eq 'rw') || ($new_access eq 'rw')) {
		return 'rw';
	} elsif(($orig_access eq 'wr') || ($new_access eq 'wr')) {
		return 'rw';
	} elsif (($orig_access eq 'r') || ($new_access eq 'r')) {
		return 'r';
	} elsif (($orig_access eq 'd') || ($new_access eq 'd')) {
		return 'd';
	}
	
	return $new_access;
}

# ---------------------------------------------------------------------------

# return user's access to a particular path
#
# returns: 'r' or 'rw' if specified, 'n' if no perm found and 
# 'd' if the user is explicitly denied access in the file.
#
sub evaluate_single_path_authz(\%$$\@) {
	
	my ($section_hash, $working_path, $user, $groups) = @_;
	
	my $access_specified = 'n';
	my $working_access = 'n';
	
	#Test::More::diag("\nWorking path = $working_path");
	# check the path
	if(exists $section_hash->{$working_path}) {
		
		# check the user first - a user level preference always overrides any other.
		if(exists $section_hash->{$working_path}{$user}) {
			$access_specified = $section_hash->{$working_path}{$user};
			#Test::More::diag("found user = $access_specified");
		} else {
		
			if(exists $section_hash->{$working_path}{'*'}) {
				# check the 'everyone' user
				$working_access = $section_hash->{$working_path}{'*'};
				$access_specified = merge_access($access_specified, $working_access);
				#Test::More::diag("found '*' user = $access_specified");
			} 
			
			# then check groups
			foreach my $group (@$groups) {
				if(exists $section_hash->{$working_path}{'@'.$group}) {
					$working_access = $section_hash->{$working_path}{'@'.$group};
					$access_specified = merge_access($access_specified, $working_access);
					#Test::More::diag("found group[$group] = $access_specified");
				}
			}
		}
	}	
	
	if($access_specified eq '') {
		$access_specified = 'd';
	}
	
	if($access_specified eq 'wr') {
		$access_specified = 'rw';    # normalize rw
	}
	
	return $access_specified;
}

# ---------------------------------------------------------------------------



1;
__END__

=head1 NAME

Atlassian::Crowd - Perl bindings for Atlassian Crowd SOAP API

=head1 SYNOPSIS

Perl interface to the Atlassian Crowd SOAP API

=head1 DESCRIPTION

Currently implemented:

authenticate_app($serverURL, $app_name, $app_credential)
authenticate_principal($serverURL, $app_name, $appToken, $principal_name, $principal_credential)
is_group_member($serverURL, $app_name, $appToken, $group_name, $principal_name)
find_group_memberships($serverURL, $app_name, $appToken, $principal_name)

=head2 EXPORT

None by default.

=head1 SEE ALSO

http://www.atlassian.com/crowd

=head1 AUTHOR

Atlassian.


=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Atlassian

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.


=cut
