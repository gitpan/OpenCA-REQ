#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::REQ;

my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/bin/openssl" );
my @tmpfiles = ("priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf" );
$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 768 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>768, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

print "Generating a Request file ... \n";
## $openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
##  	DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

my $old = new OpenCA::REQ(SHELL=>$openssl,
			  KEYFILE=>"priv.key",
			  FORMAT=>PEM,
			  DN=>[  "madwolf\@openca.org",
				 "Massimiliano Pala",
				 "CA2", "", "" ] );

print $old->getParsed()->{DN} . "\n";

## print $openssl->genReq( KEYFILE=>"priv.key", OUTFORM=>TXT,
##  	DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

## print "Parsing an SPKAC request file ... \n";
## my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"spkac.req", FORMAT=>SPKAC);
print "Parsing a RENEW request file ... \n";
## my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"renew.req", FORMAT=>RENEW);
my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"req.pem", FORMAT=>PEM);
print "Error! $!\n" if ( not $REQ );
print "REQ => $REQ\n";
print "REQ => " . $REQ->getParsed()->{DN} . "\n";

## $REQ = $old;
## print $REQ->getTXT();

print "  OPERATOR => " . $REQ->getParsed()->{OPERATOR} . "\n";
print "NOT_BEFORE => " . $REQ->getParsed()->{NOT_BEFORE} . "\n";
print "  APPROVED => " . $REQ->getParsed()->{APPROVED} . "\n";
print "        CN => " . $REQ->getParsed()->{CN} . "\n";
print "        OU => " . $REQ->getParsed()->{OU}[0] . "\n";
print "   MODULUS => " . $REQ->getParsed()->{MODULUS} . "\n";
print "     RENEW => " . $REQ->getParsed()->{RENEW} . "\n";

foreach $tmp (@tmpfiles) {
	unlink( "$tmp" );
}

exit 0; 

