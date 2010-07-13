package Apache::CrowdAuthz;

use 5.008000;
use strict;
use warnings;

require Exporter;
use Atlassian::Crowd;
use Apache::CrowdAuth;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use Apache::CrowdAuthz ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);

our $VERSION = '1.3';


# Use correct API for loaded version of mod_perl.
#
BEGIN {

    unless ( $INC{'mod_perl.pm'} ) {

        my $class = 'mod_perl';

        if ( exists $ENV{MOD_PERL_API_VERSION} && $ENV{MOD_PERL_API_VERSION} == 2 ) {
            $class = 'mod_perl2';
        }

        eval "require $class";
    }

    my @import = qw( OK HTTP_UNAUTHORIZED SERVER_ERROR M_COPY
		M_OPTIONS M_GET M_PROPFIND M_REPORT M_MOVE M_DELETE
		M_MKCOL M_PUT M_PROPPATCH M_CHECKOUT M_MERGE M_MKACTIVITY
		M_LOCK M_UNLOCK DECLINED SATISFY_ANY FORBIDDEN );

    if ( $mod_perl::VERSION >= 1.999022 ) { # mod_perl 2.0.0 RC5
        require Apache2::RequestRec;
        require Apache2::RequestUtil;
        require Apache2::RequestIO;
        require Apache2::Log;
        require Apache2::Connection;
        require Apache2::Const;
        require Apache2::Access;
		use APR::Table;
		use APR::URI;
        Apache2::Const->import(@import);
     }
     elsif ( $mod_perl::VERSION >= 1.99 ) {
        require Apache::RequestRec;
        require Apache::RequestUtil;
        require Apache::RequestIO;
        require Apache::Log;
        require Apache::Connection;
        require Apache::Const;
        require Apache::Access;
		use APR::Table;
		use APR::URI;
        Apache::Const->import(@import);
    }
    else {
        require Apache;
        require Apache::Log;
        require Apache::Constants;
        Apache::Constants->import(@import);
    }
}

use constant MP2 => $mod_perl::VERSION >= 1.999022 ? 1 : 0;

# ----------------------------------------------------------------------------

sub method_number_to_access($) {
	my ($mn) = @_;
	
	# Get access from method_number
	my $access = 'wr';
	if(($mn == M_GET) or ($mn == M_OPTIONS) or ($mn == M_PROPFIND) or ($mn == M_REPORT)) {
		$access = 'r';
	} elsif($mn == M_COPY) {
		$access = 'rr'; # recursive
	} elsif(($mn == M_MOVE) or ($mn == M_DELETE)) {
		$access = 'wr'; # write recursive
	} elsif (($mn == M_MKCOL) or ($mn == M_PUT) or ($mn == M_PROPPATCH) 
			or ($mn == M_CHECKOUT)or ($mn == M_MERGE) or ($mn == M_MKACTIVITY)
			or ($mn == M_LOCK) or ($mn == M_UNLOCK)) {
		$access = 'w';
	} else {
		$access = 'wr'; # Require most strict access for unknown methods
	}
}

# ----------------------------------------------------------------------------

# Access handler that simulates the anonymous access behaviour of mod_svn_authz
#
# Enable by putting the following in your apache conf file.
#
#     PerlAccessHandler Apache::CrowdAuthz->access_handler
#
sub access_handler {
	my $foo = shift;
	my $r = shift;

	my $rlog = $r->log;
	
	my $satisfy = $r->satisfies();
	my $authz_file = $r->dir_config('CrowdAuthzSVNAccessFile');
	
	# only allow anonymous access if
	#  1) We're using "Satisy Any" _and_ an access file
	#  2) That access file has '*' as the relevant user permission for what
	#     the user is trying to do.
	if(defined($authz_file) && ($satisfy == SATISFY_ANY)) {
		# Use the SVN-style authz file for access checks.
		my $authz_result = evaluate_access_file_authz($r, '*', '___SVNACCESS___', undef, $authz_file, undef);
		
		if($authz_result) {
			# anon access allowed.
			$rlog->debug("Anonymous SVN access ALLOWED to [".$r->uri()."])");
			return OK;
		} else {
			$rlog->debug("Anonymous SVN access DENIED to [".$r->uri()."])");
			return FORBIDDEN;
		}
	}
			
	return FORBIDDEN;
}

# ----------------------------------------------------------------------------

# Evaluate CrowdAuthzSVNAccessFile based access
sub evaluate_access_file_authz($$$$$$) {
	
	my ($r, $user, $cache_prefix, $cache, $authz_file, $apptoken) = @_;
	my $rlog = $r->log;
	
	my ($app_name, $app_credential, $cache_enabled, $cache_expiry, $soaphost) = Apache::CrowdAuth::read_options($r); 
	
	my $repos_path = Atlassian::Crowd::extract_svnrepos_path($r->location(), $r->uri());
	
	$rlog->debug("Repository uri is: $repos_path (from [".$r->uri()."])");
	
	# Get access from method_number
	my $mn = $r->method_number;
	my $access = method_number_to_access($mn);
	
	$rlog->debug("Requested access for method ".$r->method_number." is $access");
	
	my $authz_result = 0;
	
	# see if we've got a cached result
	my $got_cached;
	if(($cache_enabled eq 'on') && (defined $cache)) {
		$got_cached = $cache->get(join("", $repos_path,$cache_prefix,$user,'___ACCESS___',$access));
	}
	
	if(defined $got_cached) {
		$rlog->debug("CACHE HIT: $user for $repos_path access: $access");
		$authz_result = $got_cached;
	} else {
		if(($cache_enabled eq 'on')) {
			$rlog->debug("CACHE MISS: $user for $repos_path access: $access");
		}
		
		$rlog->debug("Using CrowdAuthzSVNAccessFile [$authz_file]");
		my %section_hash = Atlassian::Crowd::parse_svn_authz_file($authz_file);
		
		my @user_groups = ();	
		
		if($user ne "*") {		# we don't need to check groups for the '*' user
			my $groupsCached = 0;
			if(($cache_enabled eq 'on') && (defined $cache)) {
				# look up the groups in the cache
				my $groupstr = $cache->get(join("", $cache_prefix, $user,'___GROUPS___'));
				if(defined $groupstr) {
					$groupsCached = 1;
					@user_groups = split /__GROUP__/, $groupstr;
				}
			}
			if($groupsCached == 0) {
				$rlog->debug("CACHE MISS: GROUPS $user");
				@user_groups = Atlassian::Crowd::find_group_memberships($soaphost, $app_name, $apptoken, $user);
				if(($cache_enabled eq 'on') && (defined $cache)) {
					my $groupstr;
					if(@user_groups) {
						$groupstr = join '__GROUP__', @user_groups;
					} else {
						$groupstr = '';
					}
					$rlog->debug("Setting CACHE for GROUPS $user => [".join(' ', @user_groups)."]");
					$cache->set(join("", $cache_prefix, $user,'___GROUPS___'), $groupstr, $cache_expiry);
				}
			} else {
				$rlog->debug("CACHE HIT: GROUPS $user => [".join(' ', @user_groups)."]");
			}
		}
				
		$authz_result = Atlassian::Crowd::evaluate_authz(%section_hash, $repos_path, $user, @user_groups, $access);
		
		# cache this value.
		if(($cache_enabled eq 'on') && (defined $cache) && (defined $authz_result) && ($authz_result != 0)) {
			# only cache successful access attempts
			$cache->set(join("", $repos_path,$cache_prefix,$user,'___ACCESS___',$access), $authz_result, $cache_expiry);
		}
		
		# Check destination as well. 
		if(($authz_result == 1) and (($mn == M_COPY) or ($mn == M_MOVE))) {
			
			# if we're doing a move or a copy, we have to make sure
			# the user has access to the destination path as well.
			my $dest_uri = $r->headers_in->{Destination} || '';
			if($dest_uri eq '') {
				$rlog->warn('CrowdAuthz: no destination path for copy or move command');
				$authz_result = 0;
			} else {
				
				my $parsed_uri = APR::URI->parse($r->pool, $dest_uri)->path();
				$rlog->debug("parsed [$parsed_uri] from [$dest_uri]");
				
				my $dest_repos_path = Atlassian::Crowd::extract_svnrepos_path($r->location(), $parsed_uri);
				$rlog->debug("Checking destination path $dest_repos_path (from $parsed_uri)");
				$authz_result = Atlassian::Crowd::evaluate_authz(%section_hash, $dest_repos_path, $user, @user_groups, 'wr');
				if($authz_result) {
					$rlog->debug("$user is GRANTED $access access to $dest_repos_path");
				} else {
					$rlog->debug("$user is DENIED $access access to $dest_repos_path");
				}
			}
		}
	}
	if($authz_result) {
		$rlog->debug("$user is GRANTED $access access to $repos_path");
	} else {
		$rlog->debug("$user is DENIED $access access to $repos_path");
	}
	return $authz_result;
}

# ----------------------------------------------------------------------------

# Entry Point
#
sub handler {
	my $r = shift;

	my $rlog = $r->log;
	
	my $user = $r->user;
	#if ($user) {
	#	$rlog->debug('CrowdAuthz: checking '.$user.' for '.$r->uri);
	#	return Apache2::Const::OK;
	#}
	
	my ($app_name, $app_credential, $cache_enabled, $cache_expiry, $soaphost) = Apache::CrowdAuth::read_options($r); 
	
	# Both the application name and credential password need to be defined.
	if(!defined($app_name) || !defined($app_credential)) {
		$r->log_error("CrowdAuthz: CrowdAppName or CrowdAppPassword is not defined");
		$r->note_basic_auth_failure;
		return HTTP_UNAUTHORIZED;
	}
	
	my @users = ();
	my $allowedUsersStr = $r->dir_config('CrowdAllowedUsers');
	if(defined($allowedUsersStr)) {		
		@users = split /\s*,\s*/, $allowedUsersStr;		
	}
	
	# if we get a match on allowed user, then we don't need to bother with 
	# the group list
	foreach my $allowed_user (@users) {
		if($user eq $allowed_user) {
			$rlog->debug("CrowdAuthz: ".$user." allowed access through CrowdAllowedUsers");
			$rlog->info("CrowdAuthz: ".$user." allowed access to [".$r->uri."]");
			return OK;
		}
	}
	
	my $cache;
	if($cache_enabled eq 'on') {
		# Initialise the cache
		$cache = Apache::CrowdAuth::init_cache($r);
	}
	
	# authenticate the app so we can talk to crowd
	my $apptoken = Apache::CrowdAuth::get_app_token($r, $app_name, $app_credential, $soaphost, $cache, $cache_expiry);
		
	if(!defined $apptoken) {
		$r->log_error('CrowdAuthz: Failed to authenticate application.');
		# failed to auth app.
		$r->note_basic_auth_failure;
		return HTTP_UNAUTHORIZED;
	}
	
	# CrowdAuthzSVNAccessFile -------------------------------------------------
	
	my $authz_file = $r->dir_config('CrowdAuthzSVNAccessFile');
	if(defined($authz_file)) {
		
		# Use the SVN-style authz file for access checks.
		my $authz_result = evaluate_access_file_authz($r, $user, '___SVNAUTH___', $cache, $authz_file, $apptoken);		
			
		if($authz_result) {
			return OK;
		} else {
			$r->note_basic_auth_failure;
			return HTTP_UNAUTHORIZED;
		}
	}
	
	# CrowdAllowedGroups -----------------------------------------------------
	
	my @groups = ();
	# Get the list of allowed groups
	my $allowedGroupStr = $r->dir_config('CrowdAllowedGroups');
	if(defined($allowedGroupStr)) {		
		@groups = split /\s*,\s*/, $allowedGroupStr;		
	}
	
	foreach (@groups) {
		
		my $group_name = $_;
		my $read_only_requested = 0;
		# a group can be flagged as "read-only" by appending ":r" to the end
		# of the name.
		if($group_name =~ /^(.+):r$/) {
			$read_only_requested = 1;
			$group_name = $1;
			$rlog->debug("CrowdAuthz: Group [".$group_name."] is read-only");
		}
		
		# if the user is in any of the groups we pass.		
		$rlog->debug("CrowdAuthz: Checking ".$user." with group [".$_."]");
		
		my $groupmember;
		
		if($_ eq "*") {
			# special setting to enable all groups
			$groupmember = 1;
			$rlog->debug("CrowdAuthz: ".$user." is a member of [".$_."]");
			$rlog->info("CrowdAuthz: ".$user." allowed access to [".$r->uri."]");
			return OK;
		}
		
		if(defined $cache) {
			$groupmember = $cache->get($user.'___GRP___'.$_);
		}
		
		if(!defined $groupmember) {
			$rlog->debug("CrowdAuthz: CACHE MISS ".$user."[".$_."]");
			if(Atlassian::Crowd::is_group_member($soaphost, $app_name, $apptoken, $group_name, $user)) {
				$groupmember = 1;
			} else {
				$groupmember = 0;
			}
			if(defined $cache) {
				$cache->set($user.'___GRP___'.$_, $groupmember, $cache_expiry);
			}			
		} else {
			# cache hit
			$rlog->debug("CrowdAuthz: CACHE HIT ".$user."[".$_."] == ".$groupmember);
		}
		
		if($groupmember == 1) {
			$rlog->debug("CrowdAuthz: ".$user." is a member of [".$group_name."]");
			
			if($read_only_requested == 1) {
				# only give access if its a read-only HTTP request
				my $access = method_number_to_access($r->method_number);
				if($access eq 'r' || $access eq 'rr') {
					$rlog->info("CrowdAuthz: ".$user." allowed readonly access to [".$r->uri."]");
					return OK;
				}
			} else {
				$rlog->info("CrowdAuthz: ".$user." allowed any access to [".$r->uri."]");
				return OK;
			}
		}		
	}
	
	$r->note_basic_auth_failure;
	$rlog->info("CrowdAuthz: ".$user." denied access to [".$r->uri."]");
	return HTTP_UNAUTHORIZED;	
}

# ----------------------------------------------------------------------------

1;
__END__

=head1 NAME

Apache::CrowdAuthz - Apache authorization handler that uses Atlassian Crowd.

=head1 SYNOPSIS

<Location /location>

  AuthName crowd
  AuthType Basic

  PerlAuthenHandler Apache::CrowdAuth
  PerlAuthzHandler Apache::CrowdAuthz
  
  PerlSetVar CrowdAppName appname
  PerlSetVar CrowdAppPassword apppassword
  PerlSetVar CrowdSOAPURL http://localhost:8095/crowd/services/SecurityServer
  PerlSetVar CrowdCacheEnabled on
  PerlSetVar CrowdCacheLocation /tmp/CrowdAuthCache
  PerlSetVar CrowdCacheExpiry 300

  PerlSetVar CrowdAllowedGroups group1:r,group2,...
  
  require valid-user
</Location>

=head1 DESCRIPTION

This Module allows you to configure Apache to use Atlassian Crowd to 
restrict access by group membership.
	
See http://confluence.atlassian.com/x/rgGY

for full documentation.
	
Apache::CrowdAuthz requires Apache::CrowdAuth to be installed.	

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
