#!/usr/bin/perl -w
# -*- perl -*-
######################################################################
# make-ssh-known-hosts.pl -- Make ssh-known-hosts file
# Copyright (c) 1995 Tero Kivinen
# All Rights Reserved.
#
# Make-ssh-known-hosts is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY.  No author or distributor accepts
# responsibility to anyone for the consequences of using it or for
# whether it serves any particular purpose or works at all, unless he
# says so in writing.  Refer to the GNU General Public License for full
# details.
#
# Everyone is granted permission to copy, modify and redistribute
# make-ssh-known-hosts, but only under the conditions described in
# the GNU General Public License.  A copy of this license is supposed to
# have been given to you along with make-ssh-known-hosts so you can
# know your rights and responsibilities.  It should be in a file named
# gnu-COPYING-GPL.  Among other things, the copyright notice and this notice
# must be preserved on all copies.
######################################################################
#         Program: make-ssh-known-hosts.pl
#	  $Source: /var/cvs/openssh/contrib/Attic/make-ssh-known-hosts.pl,v $
#	  Author : $Author: damien $
#
#	  (C) Tero Kivinen 1995 <Tero.Kivinen@hut.fi>
#
#	  Creation          : 19:52 Jun 27 1995 kivinen
#	  Last Modification : 00:07 Jul  8 1998 kivinen
#	  Last check in     : $Date: 2000/03/15 01:13:03 $
#	  Revision number   : $Revision: 1.1 $
#	  State             : $State: Exp $
#	  Version	    : 1.343
#	  Edit time	    : 242 min
#
#	  Description       : Make ssh-known-host file from dns data.
#
#	  $Log: make-ssh-known-hosts.pl,v $
#	  Revision 1.1  2000/03/15 01:13:03  damien
#	   - Created contrib/ subdirectory. Included helpers from Phil Hands'
#	     Debian package, README file and chroot patch from Ricardo Cerqueira
#	     <rmcc@clix.pt>
#	   - Moved gnome-ssh-askpass.c to contrib directory and reomved config
#	     option.
#	   - Slight cleanup to doc files
#	
#	  Revision 1.6  1998/07/08 00:44:23  kivinen
#	  	Fixed to understand bind 8 nslookup output.
#
# Revision 1.5  1998/04/30  01:53:33  kivinen
# 	Moved kill before close and added sending SIGINT first and
# 	then 1 second sleep before sending SIGKILL.
#
#	  Revision 1.4  1998/04/17 00:39:19  kivinen
#	  	Changed to close ssh program filedescriptor before killing it.
#	  	Removed ^ from the password matching prompt.
#
#	  Revision 1.3  1997/04/17 04:21:27  kivinen
#	  	Changed to use 3des by default.
#
#	  Revision 1.2  1997/03/26 07:14:01  kivinen
#	  	Added EWOULDBLOCK.
#
#	  Revision 1.1.1.1  1996/02/18 21:38:10  ylo
#	  	Imported ssh-1.2.13.
#
# Revision 1.4  1995/10/02  01:23:45  ylo
# 	Ping packet size fixes from Kivinen.
#
# Revision 1.3  1995/08/29  22:37:39  ylo
# 	Now uses GlobalKnownHostsFile and UserKnownHostsFile.
#
# Revision 1.2  1995/07/15  13:26:37  ylo
# 	Changes from kivinen.
#
# Revision 1.1.1.1  1995/07/12  22:41:05  ylo
# Imported ssh-1.0.0.
#
#
#
# If you have any useful modifications or extensions please send them to
# Tero.Kivinen@hut.fi
#
######################################################################
# initialization

require 5.000;
use Getopt::Long;
use FileHandle;
use POSIX;
use Socket;
use Fcntl;

$version = ' $Id: make-ssh-known-hosts.pl,v 1.1 2000/03/15 01:13:03 damien Exp $ ';

$command_line = "$0 ";
foreach $a (@ARGV) {
    $command_line .= $a . " ";
}
STDERR->autoflush(1);

######################################################################
# default values for options

$debug = 5;
$defserver = '';
$bell='\a';
$public_key = '/etc/ssh_host_key.pub';
$private_ssh_known_hosts = "/tmp/ssh_known_hosts$$";
$timeout = 60;
$ping_timeout = 3;
$passwordtimeout = undef;
$trustdaemon = 1;
$domainnamesplit = 0;
$recursive = 1;

######################################################################
# Programs and their options

$nslookup = "nslookup";

$ssh="ssh -a -c 3des -x -o 'ConnectionAttempts 1' -o 'FallBackToRsh no' -o 'GlobalKnownHostsFile /dev/null' -o 'KeepAlive yes' -o 'StrictHostKeyChecking no' -o 'UserKnownHostsFile $private_ssh_known_hosts'";
$sshdisablepasswordoption="-o 'BatchMode yes' -o 'PasswordAuthentication no'";

######################################################################
# Cleanup and initialization

unlink($private_ssh_known_hosts);
$sockaddr = 'S n a4 x8';
($junk, $junk, $sshport) = getservbyname("ssh", "tcp");
if (!defined($sshport)) {
    $sshport = 22;
}
($tcpprotoname, $junk, $tcpproto) = getprotobyname('tcp');
defined($tcpprotoname) || die "getprotobyname : $!";

######################################################################
# Parse options

GetOptions("initialdns=s", "server=s", "subdomains=s",
	   "debug=i", "timeout=i", "passwordtimeout=i",
	   "trustdaemon!", "domainnamesplit", "silent",
	   "nslookup=s", "pingtimeout=i", "recursive!",
	   "keyscan", 
	   "ssh=s")
    || die "Getopt : $!";

if (defined($opt_initialdns)) { $defserver = $opt_initialdns; }

if (defined($opt_server)) { $server = $opt_server; }

if (defined($opt_subdomains)) { @subdomains = split(/,/, $opt_subdomains); }

if (defined($opt_debug)) { $debug = $opt_debug; }

if (defined($opt_timeout)) { $timeout = $opt_timeout; }

if (defined($opt_pingtimeout)) { $ping_timeout = $opt_pingtimeout; }

if (defined($opt_passwordtimeout)) {
    $passwordtimeout = $opt_passwordtimeout;
    $sshdisablepasswordoption = '';
}

if (defined($opt_trustdaemon)) { $trustdaemon = $opt_trustdaemon; }

if (defined($opt_recursive)) { $recursive = $opt_recursive; }

if (defined($opt_domainnamesplit)) { $domainnamesplit = $opt_domainnamesplit; }

if (defined($opt_silent)) { $bell = ''; }

if (defined($opt_nslookup)) { $nslookup = $opt_nslookup; }

if (defined($opt_ssh)) { $ssh = $opt_ssh; } else {
    $ssh = "$ssh $sshdisablepasswordoption";
}

if ($#ARGV == 0) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = '.*';
    $grep_no = '^$';
} elsif ($#ARGV == 1) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = $ARGV[1];
    $grep_no = '^$';
} elsif ($#ARGV == 2) {
    $domain = "\L$ARGV[0]\E";
    $grep_yes = $ARGV[1];
    $grep_no = $ARGV[2];
} else {
    print(STDERR "$0 [--initialdns initial_dns_server] [--server dns_server] [--subdomains sub.sub.domain,sub.sub,sub,] [--debug debug_level] [--timeout ssh_exec_timeout_in_secs] [--pingtimeout ping_timeout_in_secs] [--passwordtimeout timeout_for_password_in_secs] [--notrustdaemon] [--norecursive] [--domainnamesplit] [--silent] [--keyscan] [--nslookup path_to_nslookup] [--ssh path_to_ssh] full.domain [ host_info_take_regexp [ host_info_remove_regex ]]\n");
    exit(1);
}

######################################################################
# Check that ssh program exists

if (system("$ssh > /dev/null 2>&1 ") != 256) {
    print(STDERR "Error: Could not run ssh program ($ssh): $!\nError: Try giving the path to it with --ssh option\n");
    exit(1);
}

######################################################################
# Generate subdomains list

if (!$domainnamesplit) {
    debug(6, "Auto splitting host entries");
} elsif (!defined(@subdomains)) {
    debug(6, "Generating subdomain list");
    
    # split domain to pieces
    @domain_pieces = split(/\./, $domain);
    
    # add empty domain part
    push(@subdomains, '');
    
    # add rest parts, except the one before full domain name
    $entry='';
    for(; $#domain_pieces > 1; ) {
	$entry .= "." . shift(@domain_pieces);
	push(@subdomains, $entry);
    }
    
    # add full domain name
    push(@subdomains, ".$domain");
    debug(5, "Subdomain list: " . join(',', @subdomains));
} else {
    debug(5, "Using given subdomain list:" . join(',', @subdomains));
}

######################################################################
# finding SOA entry for domain

@other_servers = ();
if (!defined($server)) {
    debug(6, "Finding DNS database SOA entry");

    ($server, @other_servers) = find_soa($domain, $defserver);
    
    if (!defined($server)) {
	print(STDERR "Error: Could not find DNS SOA entry from default dns server\nError: Try giving the initial nameserver with --initialdns option\n");
	exit(1);
    } else {
	debug(5, "DNS server found : $server");
    }
} else {
    debug(5, "Using given DNS server : $server");
}

######################################################################
# Print header
    
($name, $junk, $junk, $junk, $junk, $junk, $gecos) = getpwuid($<);
$gecos =~ s/,.*$//g;

if (!defined($opt_keyscan)) {
    print(STDOUT "# This file is generated with make-ssh-known-hosts.pl\n");
    print(STDOUT "#$version\n");
    print(STDOUT "# with command line :\n");
    print(STDOUT "# $command_line\n");
    print(STDOUT "#\n");
    print(STDOUT "# The script was run by $gecos ($name) at " . localtime() . "\n");
    print(STDOUT "# using perl ($^X) version $].\n");
}

######################################################################
# Get DNS database list from server

do {    
    $domains_done{$domain} = 1;
    delete $domains_waiting{$domain};

    $hostcnt = 0;
    $cnamecnt = 0;
    $lines = 0;
    $soa = 0;
    undef %host;
    undef %cname;
    undef %hostdata;
    
  dnsagain:
    debug(1, "Getting DNS database for $domain from server $server");
    open(DNS, "echo ls -d $domain | nslookup - $server 2>&1 |") ||
	die "Error: Could not start nslookup to make dns list : $!\nError: Try giving --nslookup option and telling the path to nslookup program\n";
    
    while(<DNS>) {
	$lines++;
	chomp;
	undef $hostname if/^\s*$/;
	if (/^\s{0,1}([a-zA-Z0-9-]\S*)/) {
            $hostname = "\L$1\E";
	}
	next unless defined $hostname;
	if (/^.*\s(SOA)\s+(.*)\s*$/ || $hostname eq "SOA") {
	    undef $soa if(/^.*\s(SOA)\s+(.*)\s*$/);
	    $data = $_ if ($hostname eq "SOA");
	    $data = $2 unless $hostname eq "SOA";
	    $data =~ s/\s*;.*$//;
	    $data =~ s/^\s+//;
	    if( defined $soa ) {
		$soa .= " \L$data\E";
	    } else {
		$soa = "\L$data\E";
	    }
	    $hostname = "SOA";
        } elsif (/^.*\s(A|CNAME|NS)\s+(.*)\s*$/) {
            $host = $hostname;
	    $field = "\L$1\E";
	    $data = "\L$2\E";
	    debug(70, "Line = /$host/$field/$data/");
	    if ($host !~ /\.$/) {
		$host .= ".$domain";
	    } else {
		$host =~ s/\.$//g;
	    }
	    if ($field eq "a") {
		if ($host =~ /$domain$/) {
		    if (defined($host{$host})) {
			$host{$host} .= ",$data";
		    } else {
			$host{$host} = "$data";
			$hostcnt++;
		    }
		    debug(30, "$host A == $host{$host}");
		}
	    } elsif ($field eq "cname") {
		if ($data !~ /\.$/ && ! /^\s/ ) {
    		    $data .= ".$domain";
	        } else {
		    $data =~ s/\.$//g;
	        }
		if ($host =~ /$domain$/) {
		    if (defined($cname{$data})) {
			$cname{$data} .= ",$host";
		    } else {
			$cname{$data} = "$host";
			$cnamecnt++;
		    }
		    debug(30, "$host CNAME $data");
		    $junk = $data;
		    $data = $host;
		    $host = $junk;
		}
	    } elsif ($field eq "ns") {
		if (!defined($domains_done{$host})) {
		    if (!defined($domains_waiting{$host})) {
			debug(10, "Adding subdomain $host to domains list, with NS $data");
			$domains_waiting{$host} = $data;
			push(@domains_waiting, $host);
		    } else {
			debug(10, "Adding NS $data for domain $host");
			$domains_waiting{$host} .= ",$data";
		    }
		}
	    }
	    if (!defined($hostdata{$host})) {
		$hostdata{$host} = "$host\n$field=$data\n";
	    } else {
		$hostdata{$host} .= "$field=$data\n";
	    }
	}
    }
    close(DNS);
    if ($hostcnt == 0 && $cnamecnt == 0) {
	if ($#other_servers != -1) {
	    $server = shift(@other_servers);
	    goto dnsagain;
	}
    }
    debug(1, "Found $hostcnt hosts, $cnamecnt CNAMEs (total $lines lines)");
    if (!defined($opt_keyscan)) {
	print(STDOUT "#\n");
	print(STDOUT "# Domain = $domain, server = $server\n");
	print(STDOUT "# Found $hostcnt hosts, $cnamecnt CNAMEs (total $lines lines)\n");
	print(STDOUT "# SOA = $soa\n");
	print(STDOUT "#\n");
    }

######################################################################
# Loop through hosts and try to connect to hosts

    foreach $i (sort (keys %host)) {
	debug(50, "Host = $i, Hostdata = $hostdata{$i}");
	if ($hostdata{$i} =~ /$grep_yes/im &&
	    $hostdata{$i} !~ /$grep_no/im &&
	    $i !~ /^localhost\./ &&
	    $host{$i} !~ /^127.0.0.1$|^127.0.0.1,|,127.0.0.1$|,127.0.0.1,/) {
	    debug(2, "Trying host $i");
	    
	    @hostnames = ();
	    if (defined($cname{$i})) {
		expand($i, \@hostnames, \@subdomains);
		foreach $j (split(/,/, $cname{$i})) {
		    expand($j, \@hostnames, \@subdomains);
		}
	    } else {
		expand($i, \@hostnames, \@subdomains);
	    }
	    foreach $j (split(/,/, $host{$i})) {
		push(@hostnames, $j);
	    }
	    $hostnames = join(',', (@hostnames));
	    
	    if (defined($opt_keyscan)) {
		printf(STDOUT "$host{$i}\t$hostnames\n");
	    } elsif (try_ping($i, $host{$i})) {
		$trusted = 1;
		$err = 'Timeout expired';
		$ssh_key = try_ssh("$i");
		if (!defined($ssh_key)) {
		    $ssh_key = find_host_from_known_hosts($i);
		    $trusted = 0;
		}
		if (defined($ssh_key)) {
		    if ($trusted) {
			debug(2, "Ssh to $i succeded");
		    } else {
			debug(2, "Ssh to $i failed, using local known_hosts entry");
		    }
		    debug(4, "adding entries : $hostnames");
		    $ssh_key =~ s/root@//i;
		    if (!$trusted && !$trustdaemon) {
			print(STDOUT "# $hostnames $ssh_key\n");
		    } else {
			print(STDOUT "$hostnames $ssh_key\n");
		    }
		} else {
		    debug(2, "ssh failed : $err");
		}
	    } else {
		debug(2, "ping failed");
	    }
	} else {
	    debug(10, "Skipped host $i");
	}
    }
  again:
    $domain = shift(@domains_waiting);
    if (defined($domain)) {
	$server = $domains_waiting{$domain};
	@other_servers = split(',', $server);
	$server = shift(@other_servers);
	($server, @other_servers) = find_soa($domain, $server);
	if(!defined($server)) {
	    debug(1, "Skipping domain $domain because no DNS SOA entry found");
	    $domains_done{$domain} = 1;
	    delete $domains_waiting{$domain};
	    goto again;
	}
    }
} while ($recursive && defined($domain));

unlink($private_ssh_known_hosts);
exit (0);

######################################################################
# try_ping -- try to ping to host and return 1 if success
# $success = try_ping($host, $list_ip_addrs);

sub try_ping {
    my($host, $ipaddrs) = @_;
    my(@ipaddrs, $ipaddr, $serv, $ip);
    my($rin, $rout, $win, $wout, $nfound, $tmout, $buf, $len, $ret, $err);

    $buf = '';
    debug(51,"Trying to ping host $host");
    @ipaddrs = split(/,/, $ipaddrs);

    while ($ipaddr = shift(@ipaddrs)) {
	
	debug(55,"Trying ipaddr $ipaddr");
	
	#initialize socket
	socket(PING, PF_INET, SOCK_STREAM, $tcpproto) ||
	    die "socket failed : $!";
	setsockopt(PING, SOL_SOCKET, SO_REUSEADDR, 1) ||
	    die "setsockopt failed : $!";
	PING->autoflush(1);
	fcntl(PING, F_SETFL, fcntl(PING, F_GETFL, 0) | POSIX::O_NONBLOCK) ||
	    die "fcntl failed : $!";
	
        $ip = pack('C4', split(/\./, $ipaddr, 4));
	$serv = pack($sockaddr, AF_INET, $sshport, $ip);
	
      again:
	# try connect
	$ret = connect(PING, $serv);
	$err = $!;
	if (!$ret) {
	    debug(60, "Connect failed : $err");
	    if ($err == EINTR) {
		goto again;
	    }
	    # socket not yet connected, wait for result, it will
	    # wake up for writing when done
	    $tmout = $ping_timeout;
	    
 	    $rin = '';
	    $win = '';
	    vec($rin, fileno(PING), 1) = 1;
	    vec($win, fileno(PING), 1) = 1;
	    debug(60, "Waiting in select, rin = " . unpack('H*', $rin) .
		  ", win = " . unpack('H*', $win));
	    ($nfound) = select($rout = $rin, $wout = $win, undef, $tmout);
	    $err = $!;
	    debug(80, "Select returned $nfound, rout = " . unpack('H*', $rout) .
		  ", wout = " . unpack('H*', $wout));
	    if ($nfound != 0) {
		# connect done, read the status with sysread
		$ret = sysread(PING, $buf, 1);
		$err = $!;
		if (defined($ret) || $err == EAGAIN || $err == EWOULDBLOCK) {
		    debug(60, "Select ok, read ok ($err), returning ok");
		    # connection done, return ok
		    shutdown(PING, 2);
		    close(PING);
		    return 1;
		} else {
		    # connection failed, try next ipaddr
		    debug(60, "Select ok, read failed : $err, trying next");
		    close(PING);
		}
	    } else {
		# timeout exceeded, try next ipaddr
		debug(60, "Select failed : $err, trying next");
		close(PING);
	    }
	} else {
	    # connect succeeded, return ok.
	    debug(60, "Connect ok, returning ok");
	    shutdown(PING, 2);
	    close(PING);
	    return 1;
	}
    }
    debug(60, "Returning fail");
    return 0;
}

######################################################################
# try_ssh -- try ssh connection to host and return ssh_key if success
# if failure return undef, and set $err string to contain error message.
# $ssh_key = try_ssh($host);

sub try_ssh {
    my($host) = @_;
    my($buf, $ret, $pos, $pid, $rin, $nfound, $tmout);

    $pid = open(SSH, "$ssh $host cat $public_key 2>&1 |");
    $err = undef;

    if ($pid == 0) {
	$err = "could not open ssh connection to host";
	return undef;
    }
    $ret = 1;
    $pos = 0;
    $buf = '';
    $tmout = $timeout;
    debug(10, "Starting ssh select loop");
  loop:
    while (1) {
	
	$rin = '';
	vec($rin, fileno(SSH), 1) = 1;
	($nfound, $tmout) = select($rin, undef, undef, $tmout);
	
	# Timeout
	if ($nfound <= 0) {
	    debug(20, "Ssh select timed out");
	    kill(2, $pid); sleep(1); kill(9, $pid);
	    close(SSH);
	    $err = "Timeout expired";
	    return undef;
	}
	
	$ret = sysread(SSH, $buf, 256, $pos);
	# EOF or error
	if ($ret <= 0) {
	    # Yes, close the pipe and return
	    close(SSH);
	    debug(20, "Ssh select closed status = $?");
	    $err = "No reply from ssh";
	    return undef;
	}
	$pos += $ret;
	while ($buf =~ /^(.*)\n\r?([\000-\377]*)$/) {
	    $_ = $1;
	    $buf = $2;
	    $pos = length($buf);
	    debug(20, "Ssh select loop, line = \"$_\"");
	    if (/^connection.*refused/i) {
		$err = "connection refused";
	    } elsif (/^permission/i) {
		$err = "permission denied";
	    } elsif (/$public_key.*no\s+file/i) {
		$err = "$public_key file not found";
	    } elsif (/$public_key.*permission\s+denied/i) {
		$err = "$public_key file permission denied";
	    } elsif (/^\d+\s+\d+\s+\d/) {
		kill(2, $pid); sleep(1); kill(9, $pid);
		close(SSH);
		return $_;
	    }
	    if (defined($err)) {
		kill(2, $pid); sleep(1); kill(9, $pid);
		close(SSH);
		return undef;
	    }
	}
	if ($buf =~ /password: $/i) {
	    if (defined($passwordtimeout)) {
		$tmout = $passwordtimeout;
		print(STDERR "$bell\n\rPassword: ");
		if ($tmout == 0) {
		    $tmout = undef;
		}
	    } else {
		$tmout = 0;
	    }
	    $buf = '';
	    $pos = 0;
	}
    }
}

######################################################################
# find_hosts_from_known_hosts -- find host key from private known_hosts file
# $ssh_key = find_host_from_known_hosts($host);

sub find_host_from_known_hosts {
    my($host) = @_;
    open(KNOWNHOSTS, "<$private_ssh_known_hosts") || return undef;
    while(<KNOWNHOSTS>) {
	@_ = split(/\s+/, $_);
	if ($_[0] =~ /^$host$|^$host,|,$host$/) {
	    shift(@_);
	    close(KNOWNHOSTS);
	    return join(' ', @_);
	}
    }
    close(KNOWNHOSTS);
    return undef;
}

######################################################################
# expand -- insert expanded hostnames to hostnames table
# expand($hostname, \@hostnames, \@subdomains);

sub expand {
    my($host, $hostnames, $subdomains) = @_;
    my($newhost, $sub, $entry);

    if (!$domainnamesplit) {
	my(@domain_pieces);
	
	# split domain to pieces
	@domain_pieces = split(/\./, $host);
    
	# add rest parts, except the one before full domain name
	$entry = shift(@domain_pieces);
	
	debug(20, "Adding autosplit entry $entry");
	push(@$hostnames, $entry);
	
	for(; $#domain_pieces > 1; ) {
	    $entry .= "." . shift(@domain_pieces);
	    debug(20, "Adding autosplit entry $entry");
	    push(@$hostnames, $entry);
	}
	# add full domain name
	debug(20, "Adding autosplit entry $host");
	push(@$hostnames, $host);
    } else {
	if ($host =~ /^(.*)$domain$/i) {
	    $newhost = $1;
	    $newhost =~ s/\.$//g;
	    foreach $sub (@$subdomains) {
		$entry = $newhost . $sub;
		$entry =~ s/^\.//g;
		if ($entry ne '') {
		    debug(20, "Adding entry $entry");
		    push(@$hostnames, $entry);
		}
	    }
	}
    }
}

######################################################################
# Print debug text
# debug(text_debug_level, string)

sub debug {
    my($level, $str) = @_;
    if ($debug > $level) {
	print(STDERR "$0:debug[$level]: $str\n");
    }
}

######################################################################
# find_soa -- find soa entry for domain
# ($soa_origin, @other_servers) = find_soa($domain, $initial_server)

sub find_soa {
    my($domain, $initial_server) = @_;
    my($field, $data, $server, @other_servers);

    open(DNS, "$nslookup -type=soa $domain $initial_server 2>&1 |") ||
	die "Error: Could not start nslookup to find SOA entry for $domain : $!\nError: Try giving the path to it with --nslookup option\n";
    
    while (<DNS>) {
	if (/^[^=]*origin\s*=\s*(.*)/) {
	    $server = $1;
	    debug(10, "Found origin : $1");
	} elsif (/^[^=]*nameserver\s*=\s*(.*)\s*$/) {
	    push(@other_servers, $1);
	    debug(10, "Found nameserver : $1");
	}
    }
    close(DNS);
    return($server, @other_servers);
}

######################################################################
# make_perl_happy -- use some symbols, so perl doesn't complain so much
# make_perl_happy();

sub make_perl_happy {
    if (0) {
	print $opt_silent;
    }
}

1;
