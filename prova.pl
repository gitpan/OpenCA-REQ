#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::REQ;

my $openssl = new OpenCA::OpenSSL;
my @tmpfiles = ("priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( SHELL=>"/usr/local/ssl/bin/openssl",
		      CONFIG=>"/usr/local/mpcNET/stuff/openssl.cnf" );

$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 512 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

print "Generating a Request file ... \n";
## $openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
##  	DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

my $REQ_old = new OpenCA::REQ(SHELL=>$openssl,
			  KEYFILE=>"priv.key",
			  FORMAT=>PEM,
			  DN=>[  "madwolf\@openca.org",
				 "Massimiliano Pala",
				 "CA", "", "" ] );

print $REQ_old->getParsed()->{DN} . "\n";

## print $openssl->genReq( KEYFILE=>"priv.key", OUTFORM=>TXT,
##  	DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

## print "Parsing an SPKAC request file ... \n";
## my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"spkac.req", FORMAT=>SPKAC);
print "Parsing a RENEW request file ... \n";
my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"renew.req");
print "Error! $!\n" if ( not $REQ );

print "  OPERATOR => " . $REQ->getParsed()->{OPERATOR} . "\n";
print "NOT_BEFORE => " . $REQ->getParsed()->{NOT_BEFORE} . "\n";
print "  APPROVED => " . $REQ->getParsed()->{APPROVED} . "\n";
print "        CN => " . $REQ->getParsed()->{CN} . "\n";
print "     RENEW => " . $REQ->getParsed()->{RENEW} . "\n";

foreach $tmp (@tmpfiles) {
	unlink( "$tmp" );
}

exit 0; 

