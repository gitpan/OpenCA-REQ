## OpenCA::REQ
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
package OpenCA::REQ;

$VERSION = '0.4.25';

my %params = (
	req => undef,
	pemREQ => undef,
	derREQ => undef,
	spkacREQ => undef,
	renewREQ => undef,
	parsedSPKAC => undef,
	parsedRENEW => undef,
	parsedREQ => undef,
	backend => undef,
	reqFormat => "PEM",
);

sub new {
	my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

        bless $self, $class;

        my $keys = { @_ };
        my $infile, $tmp;

        $self->{req}       = $keys->{DATA};
        $self->{reqFormat} = $keys->{FORMAT};

        $self->{backend}    = $keys->{SHELL};
        $infile     = $keys->{INFILE};
	$keyfile    = $keys->{KEYFILE};
	
	return if (not $self->{backend});

	if( $keyfile ) {
		$self->{req} = $self->{backend}->genReq( KEYFILE=>$keys->{KEYFILE},
				  DN=>$keys->{DN},
				  OUTFORM=>$self->{reqFormat},
				  PASSWD=>$keys->{PASSWD} );

		return if ( not $self->{req} );
	}

	if( $infile ) {
                $self->{req} = "";

                open(FD, "<$infile" ) or return;
                while ( $tmp = <FD> ) {
                        $self->{req} .= $tmp;
                }
                close(FD);

		return if( not $self->{req});
        }

        if( "$self->{reqFormat}" eq "" ) {
		if( ( $self->{req} ) and ( $self->{req} =~ /SPKAC =/g ) ) {
			$self->{reqFormat} = "SPKAC";
		} elsif (($self->{req}) and ($self->{req} =~ /RENEW =/g)) {
                	$self->{reqFormat} = "RENEW";
		} else {
                	$self->{reqFormat} = "PEM";
		}
        }

        if ( $self->{req} ne "" ) {
                if ( not $self->initReq( REQ=>$self->{req},
                                          FORMAT=>$self->{reqFormat})) {
                        return;
                }

        }

        return $self;
}

sub initReq {
        my $self = shift;
        my $keys = { @_ };

        $self->{req} = $keys->{REQ};
        $self->{reqFormat} =>$keys->{FORMAT};

        return if (not $self->{req});

	if( $self->{reqFormat} !~ /SPKAC|RENEW/i ) {
        	$self->{pemREQ} = $self->{backend}->dataConvert( DATA=>$self->{req},
                                        DATATYPE=>REQUEST,
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>PEM );
        	$self->{derREQ} = $self->{backend}->dataConvert( DATA=>$self->{req},
                                        DATATYPE=>REQUEST,
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>DER );
        	$txtREQ = $self->{backend}->dataConvert( DATA=>$self->{req},
                                        DATATYPE=>REQUEST,
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>TXT );

        	$self->{parsedREQ} = $self->parseReq( REQ=>$self->{pemREQ},
						      FORMAT=>PEM );

		return if( (not $self->{pemREQ}) or (not $self->{derREQ} )
			or (not $txtREQ) or (not $self->{parsedREQ}) );
	} else {

		if ( $self->{reqFormat} =~ /SPKAC/ ) {
			$self->{spkacREQ} = $self->{req};
        		$self->{parsedSPKAC}=$self->parseReq( REQ=>$self->{req},
							FORMAT=>SPKAC );
			$self->{parsedREQ} = $self->{parsedSPKAC};

			return if( not $self->{parsedSPKAC} );

		} elsif ( $self->{reqFormat} =~ /RENEW/ ) {
			$self->{renewREQ} = $self->{req};
        		$self->{parsedRENEW}=$self->parseReq( REQ=>$self->{req},
							FORMAT=>RENEW );
			$self->{parsedREQ} = $self->{parsedRENEW};

			return if( not $self->{parsedRENEW} );
		} else {
			return;
		}
	}

        return 1;
}

sub getParsed {
        my $self = shift;

	if( $self->{reqFormat} =~ /SPKAC/i ) {
		return if( not $self->{parsedSPKAC} );
		return $self->{parsedSPKAC};
	} elsif( $self->{reqFormat} =~ /RENEW/i ) {
		return if( not $self->{parsedRENEW} );
		return $self->{parsedRENEW};
	} else {
        	return if ( not $self->{parsedREQ} );
        	return $self->{parsedREQ};
	}
}

sub parseReq {
	my $self = shift;
        my $keys = { @_ };

        my $fullReq = $keys->{REQ};
	my $format  = $keys->{FORMAT};
        my @dnList = ();

	my $beginSig = "-----BEGIN PKCS7-----";
	my $endSig   = "-----END PKCS7-----";

        my $dn, $email, $cn, @ou, $s, $l, $o, $c, $spkac;
        my $pkalg, $modulus, $exponent, $version, $serial, $certSer, $passwd;
	my $notBefore, $dataType, $reqType, $sigAlg, @exts;
        my $tmp, $tmpOU, $signature;

	my $body = "";

        return if (not $fullReq);
	my ( @lines ) = split ( /\n/, $fullReq );

	my $isSignature = 0;
	my $isSigned = 0;
	my $isBody = 1;

	foreach $line (@lines) {
		if ( $line =~ /$beginSig/ ) {
			$isSignature = 1;
			$isSigned = 1;
			$isBody = 0;
		}
		if( $line =~ /$endSig/ ) {
			$isSignature = 0;
			$signature .= "$line\n";
		}

		if( $isBody == 1 ) {
			$body .= "$line\n";
		}

		if( $isSignature == 1 ) {
			$signature .= "$line\n";
		}
	}

	my $textReq = $body;

	if( $format =~ /SPKAC|RENEW/i ) {
		## Specific for SPKAC requests...
		my @lines;

		( $reqtype  ) = ( $textReq =~ /TYPE = (.*?)\n/i );
		( $serial   ) = ( $textReq =~ /SERIAL = (.*?)\n/i );

		( $email ) = ( $textReq =~ /Email = (.*?)\n/i );
		( $cn    ) = ( $textReq =~ /CN = (.*?)\n/i );
		( $s     ) = ( $textReq =~ /S = (.*?)\n/i );
		( $l     ) = ( $textReq =~ /L = (.*?)\n/i );
		( $o     ) = ( $textReq =~ /O = (.*?)\n/i );
		( $c     ) = ( $textReq =~ /C = (.*?)\n/i );

		( $approved ) = ( $textReq =~ /APPROVED = (.*?)\n/i );
		( $notBefore) = ( $textReq =~ /NOTBEFORE = (.*?)\n/i );
		( $operator ) = ( $textReq =~ /OPERATOR = (.*?)\n/i );
		( $passwd   ) = ( $textReq =~ /PASSWD = (.*?)\n/i );
		( $spkac    ) = ( $textReq =~ /SPKAC = (.*?)\n/i );

		$dn .= "Email=$email" if ($email);
		$dn .= ", CN=$cn" if ($cn);

		@lines = split ( /\n/, $textReq );
		foreach $tmp (@lines) {
			( $tmpOU ) = ( $tmp =~ /^[\d\.]*OU = (.*)/ );
			if( $tmpOU ) {
				push @ou, $tmpOU;
				$dn .= ", OU=$tmpOU";
			}
		}

		$dn .= ", S=$s" if ($s);
		$dn .= ", L=$l" if ($l);
		$dn .= ", O=$o" if ($o);
		$dn .= ", C=$c" if ($c);

		if ( $format =~ /SPKAC/ ) {
			## Now retrieve the SPKAC crypto infos...
			$textReq = $self->{backend}->SPKAC( SPKAC=>"$body" );

			## In SPKAC files we do not have versions, so...
			$version = 0;
			$dataType = 'SPKAC';
			$reqType  = 'SPKAC';

		} elsif ( $format =~ /RENEW/i ) {
			$version = 0;

			$dataType = 'RENEW';
			$reqType  = 'RENEW';

			( $certSer ) = ( $textReq =~ /RENEW = (.*?)\n/i );

			if ( $certSer % 2 ) {
				$certSer = "0" . $certSer;
			}
		}
		
	} else {
		$textReq = $self->{backend}->dataConvert( DATA=>$textReq,
				DATATYPE=>REQUEST,
				INFORM=>$format,
				OUTFORM=>TXT);

		return if ( not $textReq );

		## Specific for NON SPKAC requests ...
        	( $version ) = ( $textReq =~ /Version: ([a-e\d]+)/i );
        	( $dn ) = ( $textReq =~ /Subject: ([^\n]+)/i );
	
		## Split the Subject into separate fields
        	@dnList = split( /\,\//, $dn );
		my $tmpOU;

               	( $email ) = ( $dn =~ /Email=([^\,^\/]+)/i );
               	( $cn    ) = ( $dn =~ /CN=([^\,^\/]+)/i );
               	( $l     ) = ( $dn =~ /L=([^\,^\/]+)/i );
               	( $s     ) = ( $dn =~ /S=([^\,^\/]+)/i );

        	## Analyze each field
        	foreach $tmp (@dnList) {
                	next if ( not $tmp );

                	## The OU variable is a list
			if( $tmp =~ /OU=/i ) {
	                        ( $tmpOU ) = ( $tmp =~ /OU=(.*)/i );
                        	push @ou, $tmpOU;
        		}
		}

               	( $o     ) = ( $dn =~ /O=([^\,^\/]+)/i );
               	( $c     ) = ( $dn =~ /C=([^\,^\/]+)/i );


		## We do not verify signature, here...
		$signature = "OK";
		$reqType    = 'PKCS#10';
		$dataType   = 'PKCS#10';
	}

	## Common Request Parsing ...
	( $pkalg ) = ( $textReq =~ /Public Key Algorithm: ([^\n]+)/i );
        ( $exponent ) = ( $textReq =~ /publicExponent: ([\d]+)/i );
        ( $modulus ) = ( $textReq =~ /Public Key: \(([\d]+)/i );

	( $sigAlg ) = ( $textReq =~ /Signature Algorithm: (.*?)\n/ );

	if( $isSigned ) {
		$reqType .= " with PKCS#7 Signature";
	}

        my $ret = {
		    DATATYPE=>$dataType,
		    TYPE=>$reqType,
		    SERIAL=>$serial,
		    RENEW=>$certSer,
		    VERSION=>$version,
		    OPERATOR=> $operator,
		    APPROVED=>$approved,
		    NOT_BEFORE=>$notBefore,
		    PASSWD=>$passwd,
                    DN => $dn,
                    EMAIL => $email,
                    CN => $cn,
                    OU => [ @ou ],
                    O => $o,
                    C => $c,
		    L => $l,
		    S => $s,
                    PK_ALGORITHM => $pkalg,
                    MODULUS => $modulus,
                    EXPONENT => $exponent,
		    SIGNATURE_ALGORITHM=> $sigAlg,
		    BODY=> $body,
		    SPKAC=> $spkac,
		    PKCS7_SIGNATURE=> $signature,
                    EXTS => [ @exts ] };
	
	return $ret;
}

sub getTXT {
	my $self = shift;
	my $ret;

	if( $self->{reqFormat} =~ /SPKAC/i ) {
		return if( not $self->{spkacREQ} );

		$ret =  $self->{req} . 
			$self->{backend}->SPKAC( $self->{spkacREQ} );
		return $ret;
	} elsif( $self->{reqFormat} =~ /RENEW/i ) {
		return if( not $self->{renewREQ} );

		$ret =  $self->{req};
		return $ret;
	} else {
		return if ( not $txtREQ );
		return $txtREQ;
	}
}

sub getPEM {
	my $self = shift;
	my $ret;

	return if( $self->{reqFormat} =~ /SPKAC/i );
	return if( $self->{reqFormat} =~ /RENEW/i );
	return if ( not $self->{pemREQ} );

	return $self->{pemREQ};
}

sub getDER {
	my $self = shift;
	my $ret;

	return if( $self->{reqFormat} =~ /SPKAC/i );
	return if( $self->{reqFormat} =~ /RENEW/i );
	return if ( not $self->{derREQ} );

	return $self->{derREQ};
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::REQ - Perl extension to easily manage Cert REQUESTs

=head1 SYNOPSIS

  use OpenCA::REQ;

=head1 DESCRIPTION

Sorry, no help available. Take a look at the prova.pl file wich
contains most of the functions available here.

Blah blah blah.

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::Configuration,
OpenCA::TRIStateCGI, OpenCA::Tools

=cut
