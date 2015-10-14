#!/usr/bin/perl -w

use strict;
use warnings;

use lib "/usr/lib/smoothwall";
use header qw( :standard );
use smoothd qw( message );
use smoothtype qw( :standard );

use Cwd;
use File::Find;

our @months = qw( Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec );
our @weekDays = qw( Sun Mon Tue Wed Thu Fri Sat );

my $GAR_Home_dir = "$swroot/mods/GAR";
our $ET_ruleage = "$swroot/snort/ET_ruleage";
our $logfile = "/var/log/snort/autoupdate-ET.log";
my $tmpdir = "/tmp/ET-tmp";

sub write_log() {
	my $message = shift(@_);
	my ($wkday, $month, $day, $time, $year) = split(/\s+/, localtime());
	if ($day < 10) {
		$day = " $day";
	}
	open LOG, ">>$logfile" or die "Couldn't open $logfile for appending: $! \n";
	print LOG "$month $day $time $message\n";
	close LOG or die "Couldn't close log after appending: $! \n";
}

# Note 1: felt appending "Index" to certain variable (better??) 
# indicated that we started counting from 0, rather than 1.
# Note 2: This is probably better handled with Date::Calc, but
# I will leave, as is, for the time being.
sub get_the_time() {
	my ($second, $minute, $hour, $dayOfMonth, $monthIndex, $yearOffset, $dayOfWeekIndex, $dayOfYear, $dayLightSavings) = localtime();
	my $year = 1900 + $yearOffset;
	if ($dayOfMonth < 10 ) { $dayOfMonth = "0$dayOfMonth"; }
	if ($hour < 10) { $hour = "0$hour"; }
	if ($minute < 10) { $minute = "0$minute"; }
	if ($second < 10) { $second = "0$second"; }
	my $theTime = "$weekDays[$dayOfWeekIndex] $months[$monthIndex] $dayOfMonth $year $hour:$minute:$second";
	return $theTime;
}

sub get_newest() {
	my $dir = shift(@_);
	-d $dir or die "get_newest: '$dir' is not a directory...\n";
	our %files;
	# my File::Find-fu is _VERY_ rusty, but this probably could be
	# written even better.
	File::Find::find(
		sub {
			my $name = $File::Find::name;
			# we only want emerging*.rules files
			if ($name =~ /emerging.*?\.rules/) {
				$files{$name} = (stat($name))[9]if ( -f $name );
			}
		}, $dir
	);

	# This will return the whole array.  But we may
	# actually want to return a reference to the hash.
	# FIX ME!!!
	return (sort { $files{$a} <=> $files{$b} } keys %files )[-1];
}

sub do_ruleage_closeout() {
	my $newest_file = 'unknown';
	&write_log("Updating $ET_ruleage file");
	my $currentTime = &get_the_time();
	&write_log("Collecting current update time: " . $currentTime );
	&write_log("Storing update time: " . $currentTime );
	open FILE, ">$ET_ruleage" or die "Couldn't open $ET_ruleage file for writing: $! \n";
	print FILE "$currentTime";
	close FILE or die "Couldn't close $ET_ruleage file: $! \n";
	$newest_file = &get_newest("$swroot/snort/rules");
	&write_log("Locating newest ET rules file: $newest_file");
	my ($a_stamp, $m_stamp) = (stat($newest_file))[8,9];
	&write_log("Collecting $newest_file\'s time stamps: ");
	&write_log("  $a_stamp  $m_stamp");
	&write_log("  ".scalar(localtime($a_stamp)));
	&write_log("  ".scalar(localtime($m_stamp)));
	&write_log("Storing time stamps to $ET_ruleage.");
	utime $a_stamp, $m_stamp, $ET_ruleage;
	&write_log("Verifying $ET_ruleage\'s time stamps:");
	undef($a_stamp); undef($m_stamp);
	($a_stamp, $m_stamp) = (stat($ET_ruleage))[8,9];
	&write_log("  $a_stamp  $m_stamp");
	&write_log("  ".scalar(localtime($a_stamp)));
	&write_log("  ".scalar(localtime($m_stamp)));
	&write_log("Setting $ET_ruleage ownership to nobody:nobody");
	chown('nobody', 'nobody', $ET_ruleage);
}

&write_log("-------------------------------------------------------------------");
&write_log("ET SNORT Rules Auto-Updater - Starting\n");
&write_log("Loading SNORT settings");

my %snortsettings;
&readhash("$swroot/snort/settings", \%snortsettings);

my $errormessage = 'start';

if ($snortsettings{'ENABLE_SNORT'} eq 'off') {
	&write_log("SNORT is not enabled.");
	&write_log("SNORT should be enabled to make running this worthwhile.");
	&write_log("Continuing anyway...");
}

# start snort version query
open SNORT, "/usr/bin/snort -V 2>&1 |" or die "Couldn't open snort: $! \n";
my ($snort_version, $display_version, $sub1, $sub2, $sub3, $sub4);
while (my $line = <SNORT>) {
	chomp($line);
	if ($line =~ /Version\s+(.*)/) {
		($display_version, $sub1, $sub2, $sub3, $sub4) = split(/ /, $1);
		$snort_version = $display_version;
		$display_version = " $sub1 $sub2 $sub3 $sub4";
	}
}
close SNORT or die "Couldn't close snort command: $! \n";

my ($ETver1, $ETver2, $ETver3, $ETver4) = split(/\./, $snort_version);
$snort_version = join(".", $ETver1, $ETver2, $ETver3);
&write_log("Working with snort $display_version - [$snort_version]");

my $curdir = getcwd();
my $url = 'http://rules.emergingthreats.net/open-nogpl/snort-'.$snort_version.'/emerging.rules.tar.gz';

unless ( -e $tmpdir && -d $tmpdir ) {
	&write_log("Creating tmp directory $tmpdir");
	unless (mkdir($tmpdir)) {
		&write_log("Uable to create directory $tmpdir\: $! ");
		die "Unable to create directory ($tmpdir): $! \n";
	}
}

&write_log("Changing current directory to $tmpdir.");
chdir($tmpdir);

my $id = 0;
while ($errormessage) {
	$id++;
	
	&write_log("Executing wget");
	open FD, "/usr/bin/wget $url 2>&1 |" or die "Couldn't open pipe to wget: $! \n";
	$errormessage = '';
	while (my $line = <FD>) {
		chomp($line);
		if ($line =~ /ERROR 403: \s+(.*)/i) {
			$errormessage = $1;
		}
		if ($line =~ /ERROR 404:\s+(.*)/i) {
			$errormessage = $1;
		}
		&write_log("    wget: $line");
	}
	close FD, or die "Couldn't close pipe to wget: $! \n";

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
		open FD, "/usr/bin/tar xvf emerging.rules.tar.gz 2>&1 |" or die "Couldn't open pipe to tar: $! \n";
		while (my $line = <FD>) {
			chomp($line);
			&write_log("    tar: $line");
		}
		close FD or die "Couldn't close pipe to tar: $! \n";

		&write_log("Changing current directory to $swroot/snort/ ");
		chdir("$swroot/snort/");
		
		$url = "dir://$tmpdir/rules";

		&write_log("Executing oinkmaster");
		open FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u $url 2>&1 |" or die "Couldn't open pipe to oinkmaster.pl: $! \n";
		while (my $line = <FD>) {
			chomp($line);
			&write_log("  oinkmaster.pl: $line");
		}
		close FD or die "Coulodn't close pipe to oinkmaster.pl: $! \n";
		if ($?) {
			&write_log("Attempt $id: $tr{'unable to fetch rules'}");
			&write_log("Reason: $errormessage");
		} else {
			&do_ruleage_closeout();

			&write_log("Updating sid-msg.map");
			system("$GAR_Home_dir/usr/bin/make-sidmap.pl");
			&write_log("Updating tor_rules.conf");
			system("$GAR_Home_dir/usr/bin/findtorrouters");
			&write_log("Executing oinkmaster to disable tor router rules");
			open FD, "/usr/bin/oinkmaster.pl -C /usr/lib/smoothwall/oinkmaster.conf -o rules -u $url 2>&1 |" or die "Couldn't open pipe to oinkmaster.pl: $! \n";
			while (my $line = <FD>) {
				chomp($line);
				&write_log("  oinkmaster2:  $line");
			}
			close FD or die "Couldn't close pipe to oinkmaster.pl: $! \n";
			
			&write_log("Setting rules ownership to nobody:nobody");
			chown("nobody:nobody", "$swroot/snort/rules/emerging*");
			&write_log("Restarting snort");
			my $success = message('snortrestart');
			if (!defined($success)) { $errormessage = 'Unable to restart snort - see /var/log/messages for details'; }
			if ($errormessage) { &write_log($errormessage); }
			undef($errormessage);
		}
	}
}

chdir($curdir);

EXIT:
if (-e $tmpdir && -d $tmpdir) {
	&write_log("Removing tmp directory");
	open FD, "/bin/rm -rvf $tmpdir 2>&1 |" or die "Couldn't open pipe to rm: $! \n";
	while (my $line = <FD>) {
		chomp($line);
		&write_log("    rm: $line");
	}
	close FD or die "Couldn't close pipe to rm: $! \n";
}

&write_log("ET SNORT Rules Auto-Updater - complete");

__DATA__