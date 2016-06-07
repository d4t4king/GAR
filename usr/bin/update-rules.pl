#!/usr/bin/perl -w

use strict;
use warnings;
# perl 5.10 and later is required for the 'use feature' feature.  This gives 
# us "switch" and "say" functionality.  At this point, we really only care
# about th "switch" (given/when) capability.
require 5.010;
#if ($] ge '5.018') {
	# perl 5.18 and later considers "smarmatch" to be an experimental feature,
	# and warns profusely, if warnings are enabled.  So disable the warnings
	# spefically for smartmatch, if perl is v5.18 or newer.
#	no warnings 'experimental::smartmatch';
#}
use feature qw( switch );

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Cwd;
use File::Find;
use Getopt::Long;
use Term::ANSIColor qw( colored );

my ($__flag__, $help);
GetOptions(
	'R|rules-group=s'	=> \$__flag__,
	'h|help'			=> \$help,
);

sub show_help() {
	print <<EOS;

Usage: $0 [-R|--rules-group] (ET|VRT|VRTC) [-h|--help]

-h|--help			Display this useful message.
-R|--rules-group		Specifies the rules group to be updated.  This 
				can be one of the following:
					ET:	Emerging Threats (emergingthreats.net)
					VRTC:	Snort VRT Community rules
					VRT:	Snort VRT Registered user/Subscriber rules*
	
* Paid subscriber rules may have yet another flag in the future (if this one doesn't match the ruleset).

EOS

}

if ($help) { &show_help && exit 0; }

# If we go any farther without the flag defined, we're just wasting memory.
if ((!defined($__flag__)) || ($__flag__ eq '')) { 
	&show_help() && die colored("\n-R option required to specify rule group to update.  See help.\n", "red"); 
} elsif ((defined($__flag__)) && ($__flag__ !~ /(?:ET|VRTC|VRT)/)) {
	&show_help() && die colored("Unrecognized value for \$__flag__: $__flag__ \n", "red");
}

our @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
our @weekDays = qw( Sun Mon Tue Wed Thu Fri Sat );

my $GAR_Home_dir = "$swroot/mods/GAR";
our %Ruleage = (
	'ET'	=> "$swroot/snort/ET_ruleage",
	'VRTC'	=> "$swroot/snort/VRTC_ruleage",
	'VRT'	=> "$swroot/snort/VRT_ruleage",
);
our $logfile = "/var/log/snort/autoupdate-rules.log";
our $tmpdir = "/tmp/tmp";
our $VRT_get_dir = 'reg-rules';
our (%usr2uid, %grp2gid);

##################################################################################
# Start of main script
##################################################################################
&get_uid(); &get_gid();
&write_log("-------------------------------------------------------------------");
&write_log("$__flag__ SNORT Rules Auto-Updater - Starting\n");
&write_log("Loading SNORT settings");

my %snortsettings;
&readhash("$swroot/snort/settings", \%snortsettings);

if ($__flag__ eq 'VRT') {
	if ($snortsettings{'OINK'} !~ /^[0-9a-fA-F]{40}$/) {
		&write_log("The oinkcode must be 40 hex digits long: $snortsettings{'OINK'}");
		&write_log("Aborting...");
		goto EXIT;
	}
}

my $errormessage = 'start';

if ($snortsettings{'ENABLE_SNORT'} eq 'off') {
	&write_log("SNORT is not enabled.");
	&write_log("SNORT should be enabled to make running this worthwhile.");
	&write_log("Continuing anyway...");
}

# start snort version query
open SNORT, "/usr/bin/snort -V 2>&1 |" or die colored("Couldn't open snort: $! \n", "bold red");
my ($snort_version, $display_version, $sub1, $sub2, $sub3, $sub4);
while (my $line = <SNORT>) {
	chomp($line);
	if ($line =~ /Version\s+(.*)/) {
		($display_version, $sub1, $sub2, $sub3, $sub4) = split(/ /, $1);
		$snort_version = $display_version;
		$snort_version =~ s/\.//g if ($__flag__ eq 'VRT');
		$display_version = " $sub1 $sub2 $sub3 $sub4";
		last;
	}
}
close SNORT or die colored("Couldn't close snort command: $! \n", "bold red");

my ($ETver1, $ETver2, $ETver3, $ETver4); 
if ($__flag__ eq 'VRT') {
	while (length($snort_version) < 4) { $snort_version .= "0"; }
	($ETver1, $ETver2, $ETver3, $ETver4) = split(/\ /, $display_version);
} else {
	# ET rules only wants the first 3 anchors of the version number
	if ($__flag__ eq 'ET') {
		($ETver1, $ETver2, $ETver3, $ETver4) = split(/\./, $snort_version);
		$snort_version = join(".", $ETver1, $ETver2, $ETver3);
	}
	# Need to see how (if) VRTC is different
}
&write_log("Working with snort $display_version - [$snort_version]");

my $curdir = getcwd();
my %url = (
	'ET'	=> 'http://rules.emergingthreats.net/open-nogpl/snort-'.$snort_version.'/emerging.rules.tar.gz',
	'VRTC'	=> 'https://s3.amazonaws.com/snort-org/www/rules/community/community-rules.tar.gz',
	'VRT'	=> 'http://www.snort.org/'.$VRT_get_dir.'/snortrules-snapshot-'.$snort_version.'.tar.gz/'.$snortsettings{'OINK'},
);

my %tar = (
	'ET'	=> 'emerging.rules.tar.gz',
	'VRTC'	=> 'community-rules.tar.gz',
	'VRT'	=> "snortules-snapshot-$snort_version.tar.gz"
);


unless ( -e $tmpdir && -d $tmpdir ) {
	&write_log("Creating tmp directory $tmpdir");
	unless (mkdir($tmpdir)) {
		&write_log("Uable to create directory $tmpdir\: $! ");
		die colored("Unable to create directory ($tmpdir): $! \n", "b9old red");
	}
}

&write_log("Changing current directory to $tmpdir.");
chdir($tmpdir);

my $id = 0;
while ($errormessage) {
	$id++;
	if ($__flag__ =~ /(?:ET|VRTC)/) {
		&write_log("Executing wget");
		open FD, "/usr/bin/wget $url{$__flag__} 2>&1 |" or die colored("Couldn't open pipe to wget (URL: $url{$__flag__}): $! \n", "bold red");
		$errormessage = '';
		while (my $line = <FD>) {
			chomp($line);
			# This could be shortened to one line, but reduces readability(?).
			if ($line =~ /ERROR 403:\s+(.*)/) { $errormessage = $1; }
			if ($line =~ /ERROR 404:\s+(.*)/) { $errormessage = $1; }
			if ($line =~ /ERROR 422:\s+(.*)/) { $errormessage = $1; }
			&write_log("    wget: $line");
		}
		close FD, or die colored("Couldn't close pipe to wget: $! \n", "bold red");

		# FIX ME!!!  There should probably be a better test here.  The variable $?
		# catches the output or status of the last command, which will be the if/else 
		# statement (assuming I'm following the flow properly) -- which should always
		# exit '0'.
		if ($?) {
			&write_log("Attempt $id: $tr{'unable to fetch rules'}");
			&write_log("Reason: $errormessage");
			if (($errormessage eq 'Not found.') || ($errormessage eq 'Forbidden.')) {
				&write_log("Will not try again...");
			} else {
				if (((defined($errormessage)) && ($errormessage ne '')) && ($id < 7)) {
					&write_log("Will try again in 5 minutes...");
					sleep 300;
				}
			}
		} else {
			&write_log("Executing tar");
			open FD, "/usr/bin/tar xvf $tar{$__flag__} 2>&1 |" or die colored("Couldn't open pipe to tar: $! \n", "bold red");
			while (my $line = <FD>) {
				chomp($line);

				&write_log("    tar: $line");
			}
			close FD or die colored("Couldn't close pipe to tar: $! \n", "bold red");
		}
	}		# end if ($__flag__ ... 		
		
	&write_log("Changing current directory to $swroot/snort/ ");
	chdir("$swroot/snort/");
			
	my $url = '';
	given ($__flag__) {
		when ('ET')		{ $url = "dir://$tmpdir/rules"; }
		when ('VRTC')	{ $url = "dir://$tmpdir/community-rules"; }
		when ('VRT')	{ $url = $url{$__flag__}; }
		default			{ print STDERR colored("You should never get here.", "blue on_white"); }
	}

	&write_log("Executing oinkmaster");
	open FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u $url 2>&1 |" or die colored("Couldn't open pipe to oinkmaster.pl: $! \n", "bold red");
	while (my $line = <FD>) {
		chomp($line);
		# This could be shortened to one line, but reduces readability(?).
		if ($line =~ /ERROR 403:\s+(.*)/) { $errormessage = $1; }
		if ($line =~ /ERROR 404:\s+(.*)/) { $errormessage = $1; }
		if ($line =~ /ERROR 422:\s+(.*)/) { $errormessage = $1; }
		&write_log("  oinkmaster.pl: $line");
	}
	close FD or die colored("Coulodn't close pipe to oinkmaster.pl: $! \n", "bold red");
	if ($?) {
		&write_log("Attempt $id: $tr{'unable to fetch rules'}");
		&write_log("Reason: $errormessage");
		if (($errormessage eq 'Not Found.') ||
			($errormessage eq 'Forbidden.') ||
			($errormessage eq 'Unprocessable Entity.')) {
			&write_log("Will not try again...");
			last;
		} else {
			if ((defined($errormessage)) && ($id < 7)) {
				&write_log("VRT 15 minute limit in effect.  Will try again in 20 minutes.");
				sleep 1200;
			}
		}
	} else {
		&do_ruleage_closeout($__flag__);

		&write_log("Updating sid-msg.map");
		system("$GAR_Home_dir/usr/bin/make-sidmap.pl");
		&write_log("Updating tor_rules.conf");
		system("$GAR_Home_dir/usr/bin/findtorrouters");
		&write_log("Executing oinkmaster to disable tor router rules");
		open FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u $url 2>&1 |" or die colored("Couldn't open pipe to oinkmaster.pl: $! \n", "bold red");
		while (my $line = <FD>) {
			chomp($line);
			&write_log("  oinkmaster2:  $line");
		}
		close FD or die colored("Couldn't close pipe to oinkmaster.pl: $! \n", "bold red");
			
		&write_log("Setting rules ownership to nobody:nobody");
		chown($usr2uid{'nobody'}, $grp2gid{'nobody'}, "$swroot/snort/rules/emerging*");
		&write_log("Restarting snort");
		my $success = message('snortrestart');
		if (!defined($success)) { $errormessage = 'Unable to restart snort - see /var/log/messages for details'; }
		if ($errormessage) { &write_log($errormessage); }
		undef($errormessage);
	}		# end if ($?)
}		# end while($erormessage)

chdir($curdir);

EXIT:
if (-e $tmpdir && -d $tmpdir) {
	&write_log("Removing tmp directory");
	open FD, "/bin/rm -rvf $tmpdir 2>&1 |" or die colored("Couldn't open pipe to rm: $! \n", "bold red");
	while (my $line = <FD>) {
		chomp($line);
		&write_log("    rm: $line");
	}
	close FD or die colored("Couldn't close pipe to rm: $! \n", "bold red");
}

&write_log("$__flag__ SNORT Rules Auto-Updater - complete");

###############################################################################
# subs
###############################################################################
# gets the UIDs of the users on the system, and populates the %usr2uid hash
sub get_uid() {
	open PWD, "</etc/passwd" or die colored("Couldn't open passwd file for reading: $! \n", "bold red");
	while (my $line = <PWD>) {
		my ($u,$id) = (split(/\:/, $line))[0,2];
		$usr2uid{$u} = $id;
	}
	close PWD or die colored("Couldn't close passwd file: $! \n", "bold red");
}

# gets the GID o f the groups on the system and populates the %grp2gid hash
sub get_gid() {
	open GRP, "</etc/group" or die colored("Couldn't open group file for reading: $! \n", "bold red");
	while (my $line = <GRP>) {
		my ($g,$id) = (split(/\:/, $line))[0,2];
		$grp2gid{$g} = $id;
	}
	close GRP or die colored("Couldln't close group file: $! \n", "bold red");
}

sub write_log() {
	my $message = shift(@_);
	my ($wkday, $month, $day, $time, $year) = split(/\s+/, localtime());
	if ($day < 10) {
		$day = " $day";
	}
	open LOG, ">>$logfile" or die colored("Couldn't open $logfile for appending: $! \n", "bold red");
	print LOG "$month $day $time $message\n";
	close LOG or die colored("Couldn't close log after appending: $! \n", "bold red");
}

# return a simplified date, if called from the add_tor_routers funtion
# Note 1: felt appending "Index" to certain variable (better??) 
# indicated that we started counting from 0, rather than 1.
# Note 2: This is probably better handled with Date::Calc, but
# I will leave, as is, for the time being.
sub get_the_time() {
	my $flag = shift(@_);
	my ($second, $minute, $hour, $dayOfMonth, $monthIndex, $yearOffset, $dayOfWeekIndex, $dayOfYear, $dayLightSavings) = localtime();
	my $year = 1900 + $yearOffset;
	if ($dayOfMonth < 10 ) { $dayOfMonth = "0$dayOfMonth"; }
	if ((defined($flag)) && ($flag eq 'ADDTOR')) {
		# need to start counting from 1 here
		# so bump the index a notch
		$monthIndex++;
		if ($monthIndex < 10) { $monthIndex = "0$monthIndex"; }
		return "${year}${monthIndex}${dayOfMonth}";
	} else {
		if ($hour < 10) { $hour = "0$hour"; }
		if ($minute < 10) { $minute = "0$minute"; }
		if ($second < 10) { $second = "0$second"; }
		my $theTime = "$weekDays[$dayOfWeekIndex] $months[$monthIndex] $dayOfMonth $year $hour:$minute:$second";
		return $theTime;
	}
}

# returns a hash of the "newest" rules files on the system
sub get_newest() {
	my $flag = shift(@_);
	my $dir = shift(@_);
	( -d $dir ) or die colored("get_newest: '$dir' is not a directory...\n", "bold red");
	our %files;
	my $search_regex;
	given($flag) {
		when ('ET')		{ $search_regex = qr/emerging.*?\.rules/; }
		when ('VRTC')	{ $search_regex = qr/community\.rules/; }
		when ('VRT')	{ $search_regex = qr/.*\.rules/; }
		default 		{ die colored("Unexpected rules group flag: $flag \n", "bold red"); }
	}
	# my File::Find-fu is _VERY_ rusty, but this probably could be
	# written even better.
	File::Find::find(
		sub {
			my $name = $File::Find::name;
			# There may (should) be a better wayt to handle this.
			# This is just an ugly hack since VRT rules
			# includes everything EXCEPT local, "community" (VRTC),
			# and "emerging.*" (ET) rules
			if ($name =~ /$search_regex/x) {		
				next if (($flag eq 'VRT') && ($name =~ /^(?:emerging.*?|community)\.rules/));
				$files{$name} = (stat($name))[9] if ( -f $name );
			}
		}, $dir
	);

	# Returns the last element in the "keys()" array
	return (sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub do_ruleage_closeout() {
	my $flag = shift(@_);
	my $newest_file = 'unknown';
	&write_log("Updating $Ruleage{$flag} file"); 
	my $currentTime = &get_the_time();
	&write_log("Collecting current update time: " . $currentTime );
	&write_log("Storing update time: " . $currentTime );
	open FILE, ">$Ruleage{$flag}" or die colored("Couldn't open $Ruleage{$flag} file for writing: $! \n", "bold red");
	print FILE "$currentTime";
	close FILE or die colored("Couldn't close $Ruleage{$flag} file: $! \n", "bold red");
	$newest_file = &get_newest($__flag__, "$swroot/snort/rules");
	die colored("Unable to determine newest rules file for $__flag__ ruleset.", "bold red") if ((!defined($newest_file)) || ($newest_file eq ''));
	&write_log("Locating newest $__flag__ rules file: $newest_file");
	my ($a_stamp, $m_stamp) = (stat($newest_file))[8,9];
	&write_log("Collecting $newest_file\'s time stamps: ");
	&write_log("  $a_stamp  $m_stamp");
	&write_log("  ".scalar(localtime($a_stamp)));
	&write_log("  ".scalar(localtime($m_stamp)));
	&write_log("Storing time stamps to $Ruleage{$flag}.");
	utime $a_stamp, $m_stamp, $Ruleage{$flag};
	&write_log("Verifying $Ruleage{$flag}\'s time stamps:");
	undef($a_stamp); undef($m_stamp);
	($a_stamp, $m_stamp) = (stat($Ruleage{$flag}))[8,9];
	&write_log("  $a_stamp  $m_stamp");
	&write_log("  ".scalar(localtime($a_stamp)));
	&write_log("  ".scalar(localtime($m_stamp)));
	&write_log("Setting $Ruleage{$flag} ownership to nobody:nobody");
	&write_log("  UID for 'nobody': $usr2uid{'nobody'}");
	&write_log("  GID for 'nobody': $grp2gid{'nobody'}");
	chown($usr2uid{'nobody'}, $grp2gid{'nobody'}, $Ruleage{$flag});
}

# needs to be fleshed out more
# depends on populated sid-msg.map file
sub add_tor_routers() {
	my $sids_ref = shift(@_);
	my $atr_date = &get_the_time('ADDTOR');
	foreach my $sid ( @{$sids_ref} ) {
		print "disablesid \$REPLY # $atr_date allow tor routers";
	}
}

# needs to be fleshed out more
# depends on populated sid-msg.map file
sub find_tor_routers() {
	
}
__DATA__
