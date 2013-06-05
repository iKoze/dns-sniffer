#!/usr/bin/perl -w
# 
# Initscript for dns-sniffer.pl by Florian Schießl (21.5.2013)
# 
# Options:
# - start
# - stop
# - restart
# 
# Return-Codes:
# - 0 on success.
# - 1 on error.
#
# Changelog:
# 21.5.2013:	Florian Schießl:
#		Script finished.
##############################################################
use strict;
##############################################################
# Configuration

my $snifferpl = "/root/dns-sniffer.pl";
my $pidfile = "/var/run/dns-sniffer.pid";

##############################################################
# Start
#
my $option = $ARGV[0] ? $ARGV[0] : '';

if($option eq "start")
{
	exit &start;
}
elsif($option eq "stop")
{
	exit &stop;
}
elsif($option eq "restart")
{
	&stop;
	sleep 2;
	exit &start;
}
else
{
	print "Usage: dns-sniffer-init.pl {start|stop|restart}\n";
}
exit 1;

sub start
{
	print "Starting '".$snifferpl."'... ";
	my $pid = &getPid;
	if($pid == -1)
	{
		system($snifferpl.' --daemon --pidfile='.$pidfile);
		sleep 1;
		if(-e $pidfile)
		{
			print "done.\n";
			return 0;
		}
		else
		{
			print "ERROR! Pidfile '".$pidfile."' was not created!\n";
		}
	}
	elsif($pid > 0)
	{
		print "ERROR! '".$snifferpl."' is already running! (PID ".$pid.")\n";
	}
	elsif($pid < 0)
	{
		print "ERROR! Invalid Pidfile '".$pidfile."'\n";
	}
	return 1;
}

sub stop
{
	print "Stopping '".$snifferpl."'... ";
	my $pid = &getPid;
	if($pid > 0)
	{

			kill 2, $pid;
			print "done.\n";
			return 0;
	}
	elsif($pid == -2)
	{
		print "ERROR: Pidfile invalid? '".$pidfile."'\n";
	}
	elsif($pid == -1)
	{
		print "ERROR: Pidfile doesn't exist '".$pidfile."'\n";
	}
	else
	{
		print "ERROR: UNKNOWN Pid return!\n";
		die "UNKNOWN Pid return";
	}
	return 1;
}

sub getPid
{
	if(-e $pidfile)
	{
		my $pid = `cat $pidfile`;
		chomp($pid);
		if($pid =~ m/^[0-9]+$/)
		{
			return $pid;
		}
		else
		{
			# Pidfile invalid
			return -2;
		}
	}
	else
	{
		# Pidfile nonexistent
		return -1;
	}
}
