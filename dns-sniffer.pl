#!/usr/bin/perl -w
# dns-sniffer.pl von Florian Schiessl (10.10.2012)
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
# | ?host?	| Hostname	| Sys::Hostname	|
# | ?rot?	| Rotation-Num	| sub rotatenum	|
# +-------------+---------------+---------------+
#
# Changelog:
# 11.10.2012:	Florian Schiessl:
#		Script fertiggestellt
# 12.10.2012:	Florian Schiessl:
#		Variablen für nicht sub dt Stunde, Minute und
#		Sekunde, Variablen für tcpdump Jahr, Monat und
#		Tag eingebaut. Tcpdump-Pakete brauchen ca. 2-3
#		Sekunden, bis sie in diesem Script übergeben
#		werden.
##############################################################
use Sys::Hostname;
##############################################################
# Konfiguration
#

##############
# Logrotate-Stunden
# Zu welcher Stunde ?rot? um eins erhöht wird.
# Auskommentieren, falls es nicht gebraucht wird.
#my @rotatehours = (6,12,18,24); # Muss 24 enthalten!

##############
# Dateiname
# Nicht vorhandene Dateien/Ordner werden automatisch erstellt
my $filename = "/var/log/dns/?host?_?pY?-?pM?-?pD?.log";

##############
# Dateiinhalt für eine DNS-Anfrage
my $pattern = "?pY?-?pM?-?pD? ?ph?:?pm?:?ps? ?type? ?subdomain? ?domain?\n";

##############
# IP, auf der gelauscht wird
my $listenip = "";

##############
# Interface, auf dem gelauscht wird
my $listenif = "eth0";

##############
# wenn Subdomain leer, ersetzen durch
my $nosubdomain = "";

##############
# Debugging; 0 = nichts ausgeben; 1 = nur Fehler; 2 = Fehler & Anfragen; 3 = alles
my $debug = 0;

##############
# Hilfsprogramme
my $tcpdump = "tcpdump";		# Pfad zu tcpdump
my $tcpdumpoptions = "-l";	# CentOS kompatibel machen ;-)
my $mkdir = "mkdir";		# Pfad zu mkdir

##############################################################
# Start
#

# Variablen belegen
my $hostname = hostname;
# Konfiguration überprüfen
if(@rotatehours)
{
	@rotatehours = sort {$a <=> $b} (@rotatehours); # Rotations-Stunden Numerisch aufsteigend sortieren
	&validaterotation; # rotatehours Konfiguration validieren
}

my $execute = "$tcpdump $tcpdumpoptions -tttt -i $listenif dst port 53 and dst host $listenip 2>/dev/null |";
&debug(3,"[debug(execute)]: $execute\n");
open INPUT, $execute or die "Can't open tcpdump. (Are you root?)";
#open INPUT, "cat newdumpfile |" or die "Can't open tcpdump. (Are you root?)";
while(<INPUT>)
{
	# Nur um auf Nummer Sicher zu gehen
	undef $time;
	undef $type;
	undef $fqdn;
	undef @fqdnparts;
	undef $domain;
	undef $subdomain;
	undef $line;
	
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
	@fqdnparts = split('\.',$fqdn); # den fqdn nach Punkten aufteilen
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
	($date,$time) = split(' ',$datetime);
	($pyear,$pmonth,$pday) = split('-',$date);
	($phour,$pminute,$psecond) = split(':',$time);

	# Aufbereitung abgeschlossen, alle Text-Variablen mit Werten belegt
	my $line = &replacevars($pattern);
	
	&debug(2,"$line");
	
	# An Datei anhängen
	&attachfile(&replacevars($filename),$line);
}
close INPUT;
exit 0;

# Catching Signals
$SIG{INT} = \&exittsk;
$SIG{TERM} = \&exittsk;
$SIG{QUIT} = \&exittsk;
$SIG{ABRT} = \&exittsk;
$SIG{HUP} = \&exittsk;

#########
# Subs

sub replacevars
{
	$line = shift;
	($year,$month,$day,$hour,$minute,$second)=(&dt('year'),&dt('month'),&dt('day'),&dt('hour'),&dt('minute'),&dt('second'));
	$line =~ s/\?Y\?/$year/;		# Jahr
	$line =~ s/\?M\?/$month/;		# Monat
	$line =~ s/\?D\?/$day/;			# Tag
	$line =~ s/\?h\?/$hour/;		# Stunde
	$line =~ s/\?m\?/$minute/;		# Minute
	$line =~ s/\?s\?/$second/;		# Sekunde
	$line =~ s/\?pY\?/$pyear/;		# Paket-Jahr
	$line =~ s/\?pM\?/$pmonth/;		# Paket-Monat
	$line =~ s/\?pD\?/$pday/;		# Paket-Tag
	$line =~ s/\?ph\?/$phour/;		# Paket-Stunde
	$line =~ s/\?pm\?/$pminute/;		# Paket-Minute
	$line =~ s/\?ps\?/$psecond/;		# Paket-Sekunde
	$line =~ s/\?type\?/$type/;		# Typ
	$line =~ s/\?subdomain\?/$subdomain/;	# Subdomain
	$line =~ s/\?domain\?/$domain/;		# Domain
	$line =~ s/\?host\?/$hostname/;		# Hostname des Systems
	if(@rotatehours)
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
	$hour = shift;
	for($i = 0; $i <= $#rotatehours; $i++)
	{
		if($hour < $rotatehours[$i] )
		{
			return $i;
		}
	}
	die "\@rotatehours ist falsch Konfiguriert! (Es muss einen Wert >= 24 enthalten.)";
}

sub debug
{
	$level = shift;
	if($debug >= $level)
	{
		print shift;
	}
}

sub dt
{
        @localtime=localtime(time);
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

sub attachfile
{
	my $fullpath = shift;
	my($path,$file) = split(/\/([^\/]+)$/, $fullpath); # Auf letzten / splitten
	&debug(3,"[file]: $fullpath\n");
	&checkpath($path); # Ordner erstellen, falls noch nicht vorhanden
	my $data = shift;
	open(FILE,">>$fullpath") or die $!;
	print FILE $data;
	close FILE;
}

sub checkpath
{
	# Ordner erstellen, falls nicht vorhanden
	$path = shift;
	if(!-e $path)
	{
		system($mkdir.' -p '.$path);
		&debug(3,"[path(created)]: $path\n");
	}
}

sub exittsk
{
	# was passiert, wenn ein Signal empfangen wird
	close INPUT;
	exit 0;
}

