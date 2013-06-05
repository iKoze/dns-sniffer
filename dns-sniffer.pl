#!/usr/bin/perl -w
# dns-sniffer.pl von Florian Schießl (10.10.2012)
#
# Dieses Script loggt DNS-Anfragen in einer oder mehreren
# Logdateien.
#
# Benötigte Programme:
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
# | ?type?	| Typ(A,MX,...)	| Net::PcapUtils|
# | ?subdomain?	| Subdomain	| Net::PcapUtils|
# | ?domain?	| Domain	| Net::PcapUtils|
# | ?srcip?	| Quell-IP	| Net::PcapUtils|
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
# 27.5.2013:	Florian Schießl:
#		Umstieg von tcpdump auf Pcap.
# 28.5.2013:	Florian Schießl:
#		Optimierungen und Ausgabe der Anfragen/sec in 
#		den Performance-Daten
# 5.6.2013:	Florian Schießl:
#		Quell-IP zu Variablen hinzugefügt.
##############################################################
use strict; # Guter Stil
use Try::Tiny; # Error-Catching
use Sys::Hostname; # Hostname
use POSIX "setsid"; # Daemonizen
use Getopt::Long qw( :config no_ignore_case bundling ); # Aufruf-Parameter
# Threading
use threads; # Threads
use threads::shared; # Zwischen den Threads geteilte Variablen
use Thread::Queue; # FIFO Warteschlange für Objekte
# Sniffing
use Net::PcapUtils; # Sniffer
use NetPacket::Ethernet qw ( :types ); # Ethernet-Paket
use NetPacket::IP qw ( :protos :versions ); # IP-Paket
use NetPacket::UDP; # UDP-Paket
use NetPacket::TCP; # TCP-Paket
use Net::DNS::Packet; # DNS-Paket
##############################################################
# Konfiguration
#

######################
# Logrotate-Stunden
# Zu welcher Stunde ?rot? um eins erhöht wird.
my $userotation = 0; # 1 = Rotation benutzen, 0 = nicht.
my @rotatehours = (6,12,18,24); # Muss 24 enthalten!

#######################
# Dateiname / Format
# Nicht vorhandene Dateien/Ordner werden automatisch erstellt
my $filename = "/var/log/dnstest/?host?_?Y?-?M?-?D?.log";

#####################################
# Dateiinhalt für eine DNS-Anfrage
my $pattern = "?Y?-?M?-?D? ?h?:?m?:?s? ?type? ?subdomain? ?domain? ?srcip?\n";

########################################
# wenn Subdomain leer, ersetzen durch
my $nosubdomain = "";

###############################
# IP, auf der gelauscht wird
my $listenip = "";

######################################
# Interface, auf dem gelauscht wird
#my $listenif = "eth0";

###################################################################
# Falls benötigt, zusätzliche Parser Threads (einer läuft immer)
my $extraparsers = 0;

#####################################################################################
# Debugging; 0 = nichts ausgeben; 1 = nur Fehler; 2 = Fehler & Anfragen; 3 = alles
my $debug = 0;

################################################################################################
# Performance-Daten auf STDERR schreiben; 0 = nichts ausgeben; 1 = performance daten ausgeben
my $perfdata = 0;

#############################################################
# Alle x Schreibvorgänge Datei zurückschreiben (schließen)
my $flush = 20;

###################
# Hilfsprogramme
my $mkdir = "mkdir";		# Pfad zu mkdir
my $syslog = "logger";		# Pfad zu Syslog (Für Start/Stop Nachrichten)

##############################################################
# Start
#

# Variablen belegen
my $daemonize = 0; # 1 = Daemon; 0 = Normal
my $pidfile = ""; # Pid Datei dieses Prozesses
my $hostname = hostname;
my $reqpersec :shared = 0; # Anfragen / Sekunde (zwischen Threads geteilte Variable)
my $parsequeue = Thread::Queue->new(); # Eingangswarteschlange
my $writequeue = Thread::Queue->new(); # Schreibwarteschlange

# Optionen holen
GetOptions(
	'd|daemon' => \$daemonize,
	'p|pidfile:s' => \$pidfile
);


# Konfiguration überprüfen
if($userotation == 1)
{
	@rotatehours = sort {$a <=> $b} (@rotatehours); # Rotations-Stunden Numerisch aufsteigend sortieren
	&validaterotation; # rotatehours Konfiguration validieren
}

# Starten
&daemonize if $daemonize == 1; # Daemon werden

# Threads Starten
threads->new(\&perfdata)->detach if defined($perfdata) && $perfdata != 0; # Perfdata-Thread starten
my $writer = threads->new(\&writer); # Writer-Thread starten
threads->new(\&parser)->detach; # Parser-Thread starten

# Zusätzliche Parser Threads starten (Sofern gewünscht)
for(my $i = 0; $i < $extraparsers; $i++)
{
	threads->new(\&parser)->detach;
}

##############################################################
# Erfolgreich gestartet!
#

&syslog("successfully started.");

# Pidfile schreiben
if($pidfile ne '')
{
	open(PIDFILE,">$pidfile") or die $!;
	print PIDFILE $$;
	close PIDFILE;
	&syslog("pidfile '".$pidfile."' created");
}

# Beenden-Signale abfangen (wichtig für clean-shutdown!)
$SIG{INT} = \&exittsk;
$SIG{TERM} = \&exittsk;
$SIG{QUIT} = \&exittsk;
$SIG{ABRT} = \&exittsk;
$SIG{HUP} = \&exittsk;

# Sniffen starten.
# Alle Pakete werden mit sub input bearbeitet.
Net::PcapUtils::loop(\&input, FILTER => 'dst port 53 and dst host '.$listenip); 
&stirb("Can't start listening!",2); # Dieser Punkt darf nicht erreicht werden!


# Hier (sub input) kommen die gesnifferten Pakete an.
# Um das blocken des Sniffers zu verhindern, werden alle ankommenden Pakete
# in die $parsequeue (Eingangswarteschlange) gesteckt, wo sie darauf warten, 
# von einem Parser bearbeitet zu werden.
sub input
{
	my ($user_data, $hdr, $packet) = @_; # Nur $packet wird gebraucht.
	$parsequeue->enqueue($packet); # Das Paket in die $parsequeue stecken.
}


############
# Threads

############
# Parser:
# Ein Parser-Thread wartet auf neue Pakete in der $parsequeue. Erscheint dort ein neues Paket,
# so wird es herausgenommen und verarbeitet. Nach der Verarbeitung kommt der aus dem Paket 
# gewonnene String zusammen mit dem Dateiname in die $writequeue (Schreibwarteschlange), wo 
# er darauf wartet, vom Writer-Thread in seine dazugehörige Datei geschrieben zu werden.
sub parser
{
	&debug(3,"[debug(parser-thread)]: started.\n");
	
	# Auf Pakete in der $parsequeue warten und herausnehmen.
	PACKET: while(my $packet = $parsequeue->dequeue())
	{
		my $type;
		my $fqdn;
		my $src_ip;
		
		##########################
		# Das Paket verarbeiten
		
		# Sensiblen Bereich absichern mit try/catch
		try
		{
			no warnings 'exiting'; # Wir wissen, dass wir mit einem next den try block verlassen.
			
			# Ethernet-Frame decodieren (OSI 2)
			my $eth_frame = NetPacket::Ethernet->decode($packet);
			# Verwerfen falls kein IP-Paket
			next PACKET if $eth_frame->{type} != ETH_TYPE_IP && $eth_frame->{type} != ETH_TYPE_IPv6;
			
			# IP-Paket decodieren (OSI 3)
			my $ip_frame = NetPacket::IP->decode($eth_frame->{data});
			# Verwerfen falls nicht TCP oder UDP
			next PACKET if $ip_frame->{proto} != IP_PROTO_TCP && $ip_frame->{proto} != IP_PROTO_UDP;
		
			my $dnspacket;
		
			# IPv4
			if($ip_frame->{ver} == IP_VERSION_IPv4)
			{
				# TCP Anfragen (OSI 4)
				if($ip_frame->{proto} == IP_PROTO_TCP)
				{
					# TCP-Frame decodieren
					my $tcp_frame = NetPacket::TCP->decode($ip_frame->{data});
					next PACKET unless $tcp_frame;
					# DNS-Paket aus Datenteil erzeugen
					$dnspacket = Net::DNS::Packet->new(\$tcp_frame->{data});
				}
			
				# UDP Anfragen (OSI 4)
				if($ip_frame->{proto} == IP_PROTO_UDP)
				{
					# UDP-Frame decodieren
					my $udp_frame = NetPacket::UDP->decode($ip_frame->{data});
					next PACKET unless $udp_frame;
					# DNS-Paket aus Datenteil erzeugen
					$dnspacket = Net::DNS::Packet->new(\$udp_frame->{data});
				}
				
				# Quell-IP
				$src_ip = $ip_frame->{src_ip};
			}
			
			
			next PACKET unless $dnspacket; # Verwerfen, falls kein DNS-Paket
			my ($dnsquestion) = $dnspacket->question;
			next PACKET unless $dnsquestion; # Verwerfen, falls keine DNS-Anfrage
			
			# Typ (A, AAAA, MX, NS,...) extrahieren
			$type = $dnsquestion->qtype;
			# FQDN extrahieren
			$fqdn = $dnsquestion->qname;
		}
		catch
		{
			# Sollte nicht auftreten aber sicher ist sicher.
			# (Besser als den Thread abschmieren zu lassen) ;-)
			no warnings 'exiting';
			&debug(1, $_."\n");
			next PACKET;
		};
		
		###############################
		# Erste Aufbereitung fertig.
		
		# Subdomain und Domain extrahieren.
		my @fqdnparts = split('\.',$fqdn); # den FQDN an den Punkten aufteilen
		
		# Beispiel: "www.sub.example.com"
		my $domain; # Die Domain bis zum 2. Level (z.B. "example.com")
		my $subdomain; # Die Subdomain (z.B. "www.sub")
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
			# Ungültige Domain
			&debug(1,"[err(invalidDomain)]: $fqdn \n");
			next;
		}
		
		################################
		# Aufbereitung abgeschlossen.
		
		# Einen String für die Logdatei anhand des Musters ($pattern) erstellen
		my $line = &replacevars($pattern, $type, $subdomain, $domain, $src_ip);
		
		# Info für die Schreibwarteschlange ($writequeue) erstellen
		my @info;
		$info[0] = &replacevars($filename, $type, $subdomain, $domain, $src_ip); # Dateiname
		$info[1] = $line; # Logdatei-String
		
		# Info für Writer in Schreibwarteschlange stecken.
		$writequeue->enqueue(\@info);
		
		&debug(2,"$line");
		$reqpersec++ if $perfdata == 1; # Für Performance-Daten ausgabe
	}
	&stirb("[thread(parser)]: died unexpected!",2);
}

############
# Writer:
# Der Writer Thread schreibt einen Logdatei-String in die entsprechende Logdatei.
# Er hält immer die aktuelle Logdatei offen, und schließt sie, sobald eine andere
# benötigt wird. Die Logdatei wird ebenfalls alle $flush einmal geschlossen und 
# erneut geöffnet, um eventuellen Verlusten vorzubeugen.
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
		
			open($fileref,">>$fullpath") or &stirb($!,2); # Neue Datei zum anhängen öffnen.
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
				open($fileref,">>$fullpath") or &stirb($!,2); # Neue Datei zum anhängen öffnen.
			}
		}
	}
	&stirb("[thread(writer)]: died unexpected!",2);
}

sub perfdata
{
	while(1)
	{
		print STDERR $reqpersec." req/sec, parsequeue: ".$parsequeue->pending.", writequeue: ".$writequeue->pending." items left.\n";
		$reqpersec = 0;
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
	my ($year,$month,$day,$hour,$minute,$second)=(&dt('year'),&dt('month'),&dt('day'),&dt('hour'),&dt('minute'),&dt('second'));
	$line =~ s/\?Y\?/$year/;			# Jahr
	$line =~ s/\?M\?/$month/;			# Monat
	$line =~ s/\?D\?/$day/;			# Tag
	$line =~ s/\?h\?/$hour/;			# Stunde
	$line =~ s/\?m\?/$minute/;			# Minute
	$line =~ s/\?s\?/$second/;			# Sekunde
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

