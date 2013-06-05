#!/usr/bin/perl -w
# dns-sniffer.pl von Florian Schießl (10.10.2012)
#
# Dieses Script loggt DNS-Anfragen in einer oder mehreren
# Logdateien.
#
# Benötigte Programme:
# - tcpdump
# - mkdir
#
# Dateiformat:
# frei Konfigurierbar.
#
# Variablen:
# Dieses Script verwendet in der Konfiguration Variablen, die
# zur Laufzeit durch ihren Wert ersetzt werden.
# Siehe sub replacevars:
# +-------------+---------------+---------------+
# | var		| value		| source	|
# +-------------+---------------+---------------+
# | ?Y?		| Jahr		| sub dt	|
# | ?M?		| Monat		| sub dt	|
# | ?D?		| Tag		| sub dt	|
# | ?h?		| Stunde	| sub dt	|
# | ?m?		| Minute	| sub dt	|
# | ?s?		| Sekunde	| sub dt	|
# | ?pY?	| Jahr		| tcpdump	|
# | ?pM?	| Monat		| tcpdump	|
# | ?pD?	| Tag		| tcpdump	|
# | ?ph?	| Stunde	| tcpdump	|
# | ?pm?	| Minute	| tcpdump	|
# | ?ps?	| Sekunde	| tcpdump	|
# | ?type?	| Typ(A,MX,...)	| tcpdump	|
# | ?subdomain?	| Subdomain	| tcpdump	|
# | ?domain?	| Domain	| tcpdump	|
# | ?srcip?	| Quell-IP	| tcpdump	|
# | ?host?	| Hostname	| Sys::Hostname	|
# | ?rot?	| Rotation-Num	| sub rotatenum	|
# +-------------+---------------+---------------+
#
# Exit-Codes:
# 0: OK
# 1: Konfigurations-Fehler
# 2: Anderer Fehler
# 
# Quellen:
# http://search.cpan.org/~rjbs/perl-5.16.3/pod/perlipc.pod
# 
# Changelog:
# 11.10.2012:	Florian Schießl:
#		Script fertiggestellt
# 12.10.2012:	Florian Schießl:
#		Variablen für nicht sub dt Stunde, Minute und
#		Sekunde, Variablen für tcpdump Jahr, Monat und
#		Tag eingebaut. Tcpdump-Pakete brauchen ca. 2-3
#		Sekunden, bis sie in diesem Script übergeben
#		werden.
# 16.5.2013:	Florian Schießl:
#		Möglichkeit eingebaut, das Script als daemon 
#		zu starten.
# 17.5.2013:	Florian Schießl:
#		Sauberes beenden implementiert.
# 21.5.2013:	Florian Schießl:
#		Pidfile und startoptionen implementiert.
# 23-24.5.2013:	Florian Schießl:
#		Multithreading implementiert.
# 5.6.2013:	Florian Schießl:
#		Quell-IP zu Variablen hinzugefügt.
##############################################################
use strict;
use Sys::Hostname;
use POSIX "setsid";
use Getopt::Long qw( :config no_ignore_case bundling );
use threads;
use Thread::Queue;
use threads::shared;
##############################################################
# Konfiguration
#

######################
# Logrotate-Stunden
# Zu welcher Stunde ?rot? um eins erhöht wird.
my $userotation = 0; # 1 = Rotation benutzen, 0 = nicht.
my @rotatehours = (6,12,18,24); # Muss 24 enthalten!

##############
# Dateiname
# Nicht vorhandene Dateien/Ordner werden automatisch erstellt
my $filename = "/var/log/dnstest/?host?_?Y?-?M?-?D?.log";

#####################################
# Dateiinhalt für eine DNS-Anfrage
my $pattern = "?Y?-?M?-?D? ?h?:?m?:?s? ?type? ?subdomain? ?domain? ?srcip?\n";

###############################
# IP, auf der gelauscht wird
my $listenip = "";

######################################
# Interface, auf dem gelauscht wird
my $listenif = "eth0";

########################################
# wenn Subdomain leer, ersetzen durch
my $nosubdomain = "";

###################################################################
# Falls benötigt, zusätzliche Parser Threads (einer läuft immer)
my $extraparsers = 0;

#####################################################################################
# Debugging; 0 = nichts ausgeben; 1 = nur Fehler; 2 = Fehler & Anfragen; 3 = alles
my $debug = 0;

###########################################
# Performance-Daten auf STDERR schreiben
my $perfdata = 0;

#############################################################
# Alle x Schreibvorgänge Datei zurückschreiben (schließen)
my $flush = 20;

###################
# Hilfsprogramme
my $tcpdump = "tcpdump";		# Pfad zu tcpdump
my $tcpdumpoptions = "-l";	# CentOS kompatibel machen ;-)
my $mkdir = "mkdir";		# Pfad zu mkdir
my $syslog = "logger";		# Pfad zu Syslog (Für Start/Stop Nachrichten)

##############################################################
# Start
#


# Variablen belegen
my $daemonize = 0; # 1 = Daemon; 0 = Normal
my $pidfile = "";
GetOptions(
	'd|daemon' => \$daemonize,
	'p|pidfile:s' => \$pidfile
);
my $hostname = hostname;
my $parsequeue = Thread::Queue->new();
my $writequeue = Thread::Queue->new();
threads->new(\&perfdata)->detach if defined($perfdata) && $perfdata != 0;
my $fileref;
my $currentfile = "";

# Konfiguration überprüfen
if($userotation == 1)
{
	@rotatehours = sort {$a <=> $b} (@rotatehours); # Rotations-Stunden Numerisch aufsteigend sortieren
	&validaterotation; # rotatehours Konfiguration validieren
}

# Starten
my $execute = "$tcpdump $tcpdumpoptions -n -tttt -i $listenif dst port 53 and dst host $listenip";
&debug(3,"[debug(execute)]: $execute\n");
&daemonize if $daemonize == 1;
my $pid;
$pid = open(INPUT, "-|"); # Fork here
defined($pid) or &stirb("Can't fork!", 2);

if(!$pid)
{
	# Child (tcpdump)
	&debug(3,"[debug(child)]: started.\n");
	#exec("sleep 300000");
	exec($execute) or &stirb("Can't open tcpdump. (Are you root?)", 2);
}

my $writer = threads->new(\&writer);

threads->new(\&parser)->detach;
for(my $i = 0; $i < $extraparsers; $i++)
{
	threads->new(\&parser)->detach;
}

&syslog("successfully started.");
if($pidfile ne '')
{
	# Pidfile schreiben
#	system($echo.' '.$$.' > '.$pidfile);
	open(PIDFILE,">$pidfile") or die $!;
	print PIDFILE $$;
	close PIDFILE;
	&syslog("pidfile '".$pidfile."' created");
}
# Catching Signals
$SIG{INT} = \&exittsk;
$SIG{TERM} = \&exittsk;
$SIG{QUIT} = \&exittsk;
$SIG{ABRT} = \&exittsk;
$SIG{HUP} = \&exittsk;

while(<INPUT>)
{
	# Alles was rein kommt den Parsern überlassen
	$parsequeue->enqueue($_);
}
close INPUT;
&stirb("end of INPUT (tcpdump died?)", 2);

############
# Threads

# Der Parser Thread holt alle Infos aus einer tcpdump Eingabe und baut daraus
# eine Zeile der Logdatei. Danach wird die Zeile dem Writer Thread übergeben.
sub parser
{
	&debug(3,"[debug(parser-thread)]: started.\n");
#	$SIG{INT} = sub 
#	{
#		&debug(3,"[thread(parser)]: exited.\n");
#		threads->exit();
#	};

	while(my $_ = $parsequeue->dequeue())
	{
		my $datetime;
		my $type;
		my $fqdn;
		my $domain;
		my $subdomain;
		my $src_ip;
	
		chomp; # Zeilenumbruch entfernen

		# Ich versuche alles so genau wie möglich zu matchen,
		# um keine falschen Daten zu bekommen. Alles was zu viel
		# gematcht wurde entferne ich in den Schritten darauf.
		# Beispiel Input String:
		# "2012-10-10 15:48:10.182596 IP 193.254.174.37.53356 > ns2.trans.net.domain: 62986 [1au] A? ad.71i.de. (38)"

		# Zeit extrahieren
		if($_ =~ m/^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]+ IP /)
		{
			$datetime = $&; # "2012-10-10 15:48:10.182596 IP "
			$datetime =~ s/\.[0-9]+ IP //; # "15:48:10"
		}
		else
		{
			&debug(1,"[errline(nodate)]: $_ \n");
			next;
		}
		
		# Quell-IP extrahieren
		if($_ =~ m/ IP [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\./)
		{
			$src_ip = $&;
			$src_ip =~ s/ IP //;
			$src_ip =~ s/\.$//;
		}
		else
		{
			&debug(1,"[errline(noip)]: $_ \n");
			next;
		}
		
		# Typ extrahieren
		if($_ =~ m/ [A-Z]+\? /)
		{
			$type = $&; # " A? "
			$type =~ s/\? $//; # " A"
			$type =~ s/^ //; # "A"
		}
		else
		{
			&debug(1,"[errline(notype)]: $_ \n");
			next;
		}
	
		# FQDN extrahieren
		if($_ =~ m/\? .+\. \([0-9]+\)$/)
		{
			$fqdn = $&; # "? ad.71i.de. (38)"
			$fqdn =~ s/^\? //; # "ad.71i.de. (38)"
			$fqdn =~ s/\. \([0-9]+\)$//; # "ad.71i.de"
			$fqdn = lc $fqdn; # die Gross-/Kleinschreibung von Domains interessiert niemanden
		}
		else
		{
			&debug(1,"[errline(nofqdn)]: $_ \n");
			next;
		}
	
		# Erste Aufbereitung fertig.

		# Subdomain und Domain extrahieren.
		my @fqdnparts = split('\.',$fqdn); # den fqdn nach Punkten aufteilen
		if($#fqdnparts > 1)
		{
			# Domain mit Subdomain
			($subdomain,$domain) = split(/\.([^\.]+\.[^\.]+)$/, $fqdn); # auf dem vorletzten Punkt splitten
		}
		elsif($#fqdnparts == 1)
		{
			# Nur Domain enthalten
			$domain = $fqdn;
			$subdomain = $nosubdomain;
		}
		else
		{
			&debug(1,"[errline(invalidDomain)]: $_ \n");
			next;
		}
	
		# Jahr, Monat, Tag, Stunde, Minute, Sekunde aus den Paketen extrahieren.
		my ($date,$time) = split(' ',$datetime);
		my ($pyear,$pmonth,$pday) = split('-',$date);
		my ($phour,$pminute,$psecond) = split(':',$time);

		my @replacedata = ($type, $subdomain, $domain, $src_ip, $pyear, $pmonth, $pday, $phour, $pminute, $psecond);

		# Aufbereitung abgeschlossen, alle Text-Variablen mit Werten belegt
		my $line = &replacevars($pattern, @replacedata);
	
		&debug(2,"$line");
		
		# An Writer übergeben
		my @info = (&replacevars($filename, @replacedata),$line);
		$writequeue->enqueue(\@info);
	}
	&stirb("[thread(parser)]: died unexpected!",2);
}

# Der Writer Thread schreibt eine Zeile in die entsprechende Logdatei.
# Er hält immer die aktuelle Logdatei offen, und schließt sie, sobald eine
# neue kommt.
sub writer
{
	&debug(3,"[debug(writer-thread)]: started.\n");
	my $currentfile = "";
	my $fileref;
	my $counter = 0;
	while(my $inforef = $writequeue->dequeue())
	{
		my @info = @$inforef;
		my $fullpath = $info[0];
		my $data = $info[1];
		if($fullpath eq "")
		{
			# Beenden Event.
			close $fileref if $currentfile ne "";
			
			&debug(3,"[debug(writer-thread)]: closed file '".$currentfile."' and quitted.\n");
			$currentfile = "";
			threads->exit(0);
		}
		elsif($fullpath ne $currentfile)
		{
			# Datei hat sich geändert.
			&debug(3,"[debug(writer-thread)]: filechange to: '".$fullpath."'\n");
			
			close $fileref if $currentfile ne ""; # Alte Datei schließen, falls geöffnet.
			$currentfile = "";

			# Ordner erstellen, falls noch nicht vorhanden
			my($path,$file) = split(/\/([^\/]+)$/, $fullpath); # Auf letzten / splitten
			&checkpath($path);
		
			open($fileref,">>$fullpath") or die $!; # Neue Datei zum anhängen öffnen.
			$currentfile = $fullpath;
		}
		if($currentfile ne "" && $data ne "")
		{
			print $fileref $data; # Datensatz in Datei schreiben.
			++$counter;
			if($counter == $flush)
			{
				$counter = 0;
				close $fileref;
				open($fileref,">>$fullpath") or die $!; # Neue Datei zum anhängen öffnen.
			}
		}
	}
	&stirb("[thread(writer)]: died unexpected!",2);
}

sub perfdata
{
	while(1)
	{
		print STDERR "parsequeue: ".$parsequeue->pending.", writequeue: ".$writequeue->pending." items left.\n";
		sleep 1;
	}
}

#########
# Subs

sub replacevars
{
	my $line = shift;
	my $type = shift;
	my $subdomain = shift;
	my $domain = shift;
	my $src_ip = shift;
	my $pyear = shift;
	my $pmonth = shift;
	my $pday = shift;
	my $phour = shift;
	my $pminute = shift;
	my $psecond = shift;
	my ($year,$month,$day,$hour,$minute,$second)=(&dt('year'),&dt('month'),&dt('day'),&dt('hour'),&dt('minute'),&dt('second'));
	$line =~ s/\?Y\?/$year/;			# Jahr
	$line =~ s/\?M\?/$month/;			# Monat
	$line =~ s/\?D\?/$day/;			# Tag
	$line =~ s/\?h\?/$hour/;			# Stunde
	$line =~ s/\?m\?/$minute/;			# Minute
	$line =~ s/\?s\?/$second/;			# Sekunde
	$line =~ s/\?pY\?/$pyear/;			# Paket-Jahr
	$line =~ s/\?pM\?/$pmonth/;			# Paket-Monat
	$line =~ s/\?pD\?/$pday/;			# Paket-Tag
	$line =~ s/\?ph\?/$phour/;			# Paket-Stunde
	$line =~ s/\?pm\?/$pminute/;			# Paket-Minute
	$line =~ s/\?ps\?/$psecond/;			# Paket-Sekunde
	$line =~ s/\?type\?/$type/;			# Typ
	$line =~ s/\?subdomain\?/$subdomain/;	# Subdomain
	$line =~ s/\?domain\?/$domain/;		# Domain
	$line =~ s/\?srcip\?/$src_ip/;		# Quell-IP
	$line =~ s/\?host\?/$hostname/;		# Hostname des Systems
	if($userotation == 1)
	{
		my $rot = &rotatenum($hour);
		$line =~ s/\?rot\?/$rot/;
	}
	return $line;
}

sub validaterotation
{
	&debug(3,"[debug]: Folgende Nummern werden den Stunden zugewiesen (h:n):\n");
	for(my $i = 0; $i <= 23; $i++)
	{
		&debug(3,"$i:");
		&debug(3,&rotatenum($i));
		&debug(3,"\n");
	}
}

sub rotatenum
{
	my $hour = shift;
	for(my $i = 0; $i <= $#rotatehours; $i++)
	{
		if($hour < $rotatehours[$i] )
		{
			return $i;
		}
	}
	&stirb("\@rotatehours ist falsch Konfiguriert! (Es muss einen Wert >= 24 enthalten.)",1);
}

sub debug
{
	my $level = shift;
	my $message = shift;
	if($debug >= $level)
	{
		print STDERR $message;
	}
	&syslog($message) if $level == 3;
}

sub dt
{
        my @localtime=localtime(time);
        if ($_[0] eq 'year')
        {return $localtime[5]+1900}
        elsif ($_[0] eq 'month')
        {return &attachleading(2,$localtime[4]+1)}
        elsif ($_[0] eq 'day')
        {return &attachleading(2,$localtime[3])}
        elsif ($_[0] eq 'hour')
        {return &attachleading(2,$localtime[2])}
        elsif ($_[0] eq 'minute')
        {return &attachleading(2,$localtime[1])}
        elsif ($_[0] eq 'second')
        {return &attachleading(2,$localtime[0])}
        else {return "dterror"}
}

sub attachleading
{
        (my $length, my $string) = @_; # Gesamtlänge des Strings, String
        for (my $count = $length - length($string); $count>0; --$count)
        {
                $string = "0$string";
        }
        return $string;
}

sub checkpath
{
	# Ordner erstellen, falls nicht vorhanden
	my $path = shift;
	if(!-e $path)
	{
		system($mkdir.' -p '.$path);
		&debug(3,"[path(created)]: $path\n");
	}
}

sub daemonize
{
	&debug(3,"daemonizing...\n");
	chdir("/") || &stirb("can't chdir to /: $!",2);
	open(STDIN, "< /dev/null") || &stirb("can't read /dev/null: $!",2);
	open(STDOUT, "> /dev/null") || &stirb("can't write to /dev/null: $!",2); # Siehe hier.
	defined(my $pid = fork()) || &stirb("can't fork: $!",2);
	exit if $pid; # non-zero now means I am the parent
	(setsid() != -1) || &stirb("Can't start a new session: $!",2);
	open(STDERR, ">&STDOUT") || &stirb("can't dup stdout: $!",2);
	&debug(3,"done\n"); # Sollte nicht mehr ausgegeben werden!
}

sub stirb
{
	my $message = shift;
	my $code = shift;
	$message = "Configuration-Error: ".$message if $code == 1;
	$message = "ERROR: ".$message if $code == 2;
	&syslog($message);
	print $message."\n";
	exit $code;
}

sub syslog
{
	my $message = shift;
	system($syslog.' "[DNS-Sniffer]: '.$message.'"');
}

sub exittsk
{
	# was passiert, wenn ein Signal empfangen wird
	&syslog("Received Signal,... quitting.");
	kill 2, $pid if $pid; # send INT to fork (tcpdump)
	my @test = ("","");
	$writequeue->enqueue(\@test); # Datei Schließen & writer beenden.
	$writer->join; # Warten, bis sich writer beendet.
	if($pidfile ne '')
	{
		unlink($pidfile);
		&debug(3,"[pidfile(removed)]: '".$pidfile."'\n");
	}
	&syslog("ended gracefully.");
	exit 0;
}

