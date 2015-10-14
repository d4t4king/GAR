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

my $GAR_Home-dir = "$swroot/mods/GAR";
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
	$theTime = "$weekDays[$dayOfWeekIndex] $months[$dayOfMonthIndex] $dayOfMonth $year $hour:$minute:$second";
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
			my $name = $Fie::Find::name;
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
	$currentTime = &get_the_time();
	&write_log("Collecting current update time: " . &currentTime );
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
	undef($a_stamp, $m_stamp);
	($a_stamp, $m_stamp) = (stat($ET_ruleage))[8,9];
	&write_log("  $a_stamp  $m_stamp");
	&write_log("  ".scalar(localtime($a_stamp)));
	&write_log("  ".scalar(localtime($m_stamp)));
	&write_log("Setting $ET_ruleage ownership to nobody:nobody");
	chown('nobody', 'nobody', $ET_ruleage):
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
my ($display_version, $sub1, $sub2, $sub3, $sub4);
while (my $line = <SNORT>) {
	chomp($line);
	if ($line =~ /Version\s+(.*)/) {
		($display_version, $sub1, $sub2, $sub3, $sub4) = split(/ /, $1);
		$display_version = " $sub1 $sub2 $sub3 $sub4";
	}
}
close SNORT or die "Couldn't close snort command: $! \n";

