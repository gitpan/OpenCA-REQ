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

use strict;

package OpenCA::REQ;

$OpenCA::REQ::VERSION = '0.7.31a';

my %params = (
	req => undef,
	item => undef,
	pemREQ => undef,
	derREQ => undef,
	txtREQ => undef,
	spkacREQ => undef,
	renewREQ => undef,
	revokeREQ => undef,
	parsedSPKAC => undef,
	parsedRENEW => undef,
	parsedREVOKE => undef,
	parsedItem => undef,
	backend => undef,
	beginHeader => undef,
	endHeader => undef,
	beginSignature => undef,
	endSignature => undef,
	reqFormat => undef,
);

sub new {
	my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

        bless $self, $class;

	$self->{beginHeader} 	= "-----BEGIN HEADER-----";
	$self->{endHeader} 	= "-----END HEADER-----";
	$self->{beginSignature} = "-----BEGIN PKCS7-----";
	$self->{endSignature} 	= "-----END PKCS7-----";
	$self->{reqFormat} 	= "PEM";

        my $keys = { @_ };
        my ( $infile, $keyfile, $tmp );

        $self->{req}       = $keys->{DATA};
        $self->{reqFormat} = ( $keys->{FORMAT} or $keys->{INFORM} );

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

        if( $self->{reqFormat} eq "" ) {
		if( ( $self->{req} ) and ( $self->{req} =~ /SPKAC =/g ) ) {
			$self->{reqFormat} = "SPKAC";
		} elsif (($self->{req}) and ($self->{req} =~ /RENEW =/g)) {
                	$self->{reqFormat} = "RENEW";
		} elsif (($self->{req}) and ($self->{req} =~ /REVOKE =/g)) {
                	$self->{reqFormat} = "REVOKE";
		} else {
                	$self->{reqFormat} = "PEM";
		}
        }

        if ( $self->{req} ne "" ) {
		$self->{item} = $self->{req};

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

        $self->{reqFormat} 	= $keys->{FORMAT};
	$self->{req}		= $self->getBody( REQUEST=> $keys->{REQ});

        return if (not $self->{req});

	if( $self->{reqFormat} !~ /SPKAC|RENEW|REVOKE/i ) {
        	$self->{pemREQ} = $self->{backend}->dataConvert( 
					DATA=>$self->{req},
                                        DATATYPE=>"REQUEST",
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>"PEM" );

        	$self->{derREQ} = $self->{backend}->dataConvert( 
					DATA=>$self->{req},
                                        DATATYPE=>"REQUEST",
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>"DER" );

        	$self->{txtREQ} = $self->{backend}->dataConvert(
					DATA=>$self->{req},
                                        DATATYPE=>"REQUEST",
                                        INFORM=>$self->{reqFormat},
                                        OUTFORM=>"TXT" );

       		$self->{parsedItem} = $self->parseReq( REQ=>$keys->{REQ},
						FORMAT=>$self->{reqFormat} );

		return if( (not $self->{pemREQ}) or (not $self->{derREQ} )
			or (not $self->{txtREQ}) or (not $self->{parsedItem}) );
	} else {

		if ( $self->{reqFormat} =~ /SPKAC/ ) {
			$self->{spkacREQ} = $self->{req};
        		$self->{parsedSPKAC}=$self->parseReq( REQ=>$keys->{REQ},
							FORMAT=>"SPKAC" );
			$self->{parsedItem} = $self->{parsedSPKAC};

			return if( not $self->{parsedSPKAC} );

		} elsif ( $self->{reqFormat} =~ /RENEW/ ) {
			$self->{renewREQ} = $self->{req};
        		$self->{parsedRENEW}=$self->parseReq( REQ=>$keys->{REQ},
							FORMAT=>"RENEW" );
			$self->{parsedItem} = $self->{parsedRENEW};

			return if( not $self->{parsedRENEW} );
		} elsif ( $self->{reqFormat} =~ /REVOKE/ ) {
			$self->{revokeREQ} = $self->{req};
        		$self->{parsedREVOKE}=
				$self->parseReq( REQ=>$keys->{REQ},
					FORMAT=>"REVOKE" );
			$self->{parsedItem} = $self->{parsedREVOKE};

			return if( not $self->{parsedREVOKE} );
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
	} elsif( $self->{reqFormat} =~ /REVOKE/i ) {
		return if( not $self->{parsedREVOKE} );
		return $self->{parsedREVOKE};
	} else {
        	return if ( not $self->{parsedItem} );
        	return $self->{parsedItem};
	}
}

sub getHeader {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};

	my ( $txt, $ret, $i, $key, $val );

	my $beginHeader = $self->{beginHeader};
	my $endHeader = $self->{endHeader};

	if( ($txt) = ( $req =~ /$beginHeader\n([\s\S\n]+)\n$endHeader/) ) {
		foreach $i ( split ( /\n/, $txt ) ) {
			$i =~ s/\s*=\s*/=/;
			( $key, $val ) = ( $i =~ /^([^=]*)\s*=\s*(.*)\s*/ );
			$ret->{$key} = $val;
		}
	}

	return $ret;
}

sub getSignature {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};

	my $ret;
	my $beginSig 	= $self->{beginSignature};
	my $endSig 	= $self->{endSignature};

	## Let's get text between the two headers, included
	if( ($ret) = ( $req =~ /($beginSig[\S\s\n]+$endSig)/m) ) {
		return $ret
	} else {
		return;
	}

	return $ret;
}

sub getBody {
	my $self = shift;
	my $keys = { @_ };

	my $ret = $keys->{REQUEST};

	my $beginHeader 	= $self->{beginHeader};
	my $endHeader 		= $self->{endHeader};

	my $beginSig 		= $self->{beginSignature};
	my $endSig 		= $self->{endSignature};

	## Let's throw away text between the two headers, included
	$ret =~ s/($beginHeader[\S\s\n]+$endHeader\n*)//;

	## Let's throw away text between the two headers, included
	$ret =~ s/($beginSig[\S\s\n]+$endSig)//;

	$ret =~ s/\n$//;

	return $ret
}

sub parseReq {
	my $self = shift;
        my $keys = { @_ };

        my $fullReq = $keys->{REQ};
	my $format  = $keys->{FORMAT};

        my @dnList = ();
	my @ou = ();
	my @exts = ();

	my ( $ret, $tmp, $key, $val, $tmpOU, $ra, $textReq );

        return if (not $fullReq);

	my ( @lines ) = split ( /\n/, $fullReq );

	$ret->{SIGNATURE} 	= $self->getSignature( REQUEST=>$fullReq );
	$ret->{HEADER} 		= $self->getHeader( REQUEST=>$fullReq );
	$ret->{BODY}		= $self->getBody( REQUEST=> $fullReq);
	$ret->{ITEM}		= $self->{item};

	$textReq = $ret->{BODY};

	if( $format =~ /SPKAC|RENEW|REVOKE/i ) {
		## Specific for SPKAC requests...
		my ( @reqLines );

		@reqLines = split( /\n/ , $textReq );
		for $tmp (@reqLines) {

			if( $tmp =~ /^[\d\.]*OU/ ) {
				my $tmpOU;

				( $tmpOU ) = ( $tmp =~ /OU\s*=\s*(.*)/);
				push ( @ou, $tmpOU );

			} else {
				## $tmp =~ s/\s*=\s*/=/;
				($key,$val)=($tmp =~ /([\w]+)\s*=\s*(.*)\s*/ );
				$key = uc( $key );

				$ret->{$key} = $val;
			}
		}

		$ret->{OU} = [ @ou ];

		if( not exists $ret->{DN} ) {
			$ret->{DN} = "Email=$ret->{EMAIL}" if ( $ret->{EMAIL});
			$ret->{DN} .= ", CN=$ret->{CN}" if ($ret->{CN});

			for $tmp ( @ou ) {
				$ret->{DN} .= ", OU=$tmp";
			}

			$ret->{DN} .= ", S=$ret->{S}" if ($ret->{S});
			$ret->{DN} .= ", L=$ret->{L}" if ($ret->{L});
			$ret->{DN} .= ", O=$ret->{O}" if ($ret->{O});
			$ret->{DN} .= ", C=$ret->{C}" if ($ret->{C});
		};

		if ( $format =~ /SPKAC/ ) {
			## Now retrieve the SPKAC crypto infos...
			$textReq=$self->{backend}->SPKAC( SPKAC=>$ret->{BODY});

			$ret->{VERSION} 	= 1;
			$ret->{TYPE}  		= 'SPKAC';

		} elsif ( $format =~ /RENEW/i ) {

			$ret->{VERSION} 	= 1;
			$ret->{TYPE}  		= 'RENEW';

			if ( $ret->{RENEW} % 2 ) {
				$ret->{RENEW} = "0" . $ret->{RENEW};
			}

		} elsif ( $format =~ /REVOKE/i ) {

			$ret->{VERSION} 	= 1;
			$ret->{TYPE}  		= 'REVOKE';

			if ( $ret->{REVOKE} % 2 ) {
				$ret->{REVOKE} = "0" . $ret->{REVOKE};
			}
		}
		
	} else {
		$textReq = $self->{backend}->dataConvert( DATA=>$textReq,
			DATATYPE=>"REQUEST", INFORM=>$format, OUTFORM=>"TXT");

		return if ( not $textReq );

		## Specific for NON SPKAC requests ...
        	( $ret->{VERSION} ) = ( $textReq =~ /Version: ([a-e\d]+)/i );
        	( $ret->{DN} ) = ( $textReq =~ /Subject: (.*)\n/i );

               	( $ret->{EMAIL} ) = ($ret->{DN}=~ 
					/Email=([^\,\/\n]+\@[^\,\/\n]+)/i);

               	( $ret->{CN}    ) = ( $ret->{DN} =~ /CN=([^\,\/\n]+)/i );
               	( $ret->{L}     ) = ( $ret->{DN} =~ /L=([^\,\/\n]+)/i );
               	( $ret->{S}     ) = ( $ret->{DN} =~ /S=([^\,\/\n]+)/i );
               	( $ret->{O}     ) = ( $ret->{DN} =~ /O=([^\,\/\n]+)/i );

               	( $ret->{C}     ) = ( $ret->{DN} =~ /C=([^\,\/\n]+)/i );

		## Split the Subject into separate fields
        	@dnList = grep ( /OU=/ , 
				grep( ! /,/ , split( /(\, |\/)/, $ret->{DN} )));
        	## Analyze each field
        	foreach $tmp (@dnList) {
                	next if ( not $tmp );

                	## The OU variable is a list
			( $tmpOU ) = ( $tmp =~ /OU=(.*)/i );
                       	push ( @{$ret->{OU}}, $tmpOU );
		}

		## We do not verify signature, here...
		## $ret->{VERSION} 	= 0;
		if( exists $ret->{HEADER}->{TYPE} ) {
			$ret->{TYPE} = $ret->{HEADER}->{TYPE};
		} else {
			$ret->{TYPE}  		= 'PKCS#10';
		}
	}

	## Common Request Parsing ...
	( $ret->{PK_ALGORITHM})=($textReq =~ /Public Key Algorithm: ([^\n]+)/i);
        ( $ret->{EXPONENT} ) = ( $textReq =~ /Exponent: ([\d]+)/i );
       	( $ret->{KEYSIZE} )  = ( $textReq =~ /Modulus[\s]*\(([\d]+)/gi );

	( $ret->{SIG_ALGORITHM})=($textReq =~ /Signature Algorithm: (.*?)\n/ );

	$ret->{TYPE} .= " with PKCS#7 Signature" if ( $ret->{SIGNATURE} );

	return $ret;
}

sub update {
	my $self = shift;
	my $keys = { @_ };

	my ( $target, $key, $val );
	
	## We actually can modify only TEXT requests...
	return if ( $self->getParsed()->{TYPE} !~ /SPKAC|RENEW|REVOKE/ );

	while ( ($key, $val) = each %$keys ) {

		if( exists($self->getParsed()->{HEADER}->{$key})) {
			$target = $self->getParsed()->{HEADER};
		} else {
			$target = $self->getParsed();
		}

		if ( exists($target->{$key}) ) {
			$self->{req} =~ s/^($key\s*=\s*)(.*?)$/$1$val/m;
			$self->{item} = $self->{req};

			$target = $val;
		}
	}
}


sub getTXT {
	my $self = shift;
	my $ret;

	if( $self->{reqFormat} =~ /SPKAC/i ) {
		return if( not $self->{spkacREQ} );

		$ret =  $self->{req} . 
			$self->{backend}->SPKAC( $self->{spkacREQ} );
		return $ret;
	} elsif( $self->{reqFormat} =~ /RENEW|REVOKE/i ) {
		return if( not $self->{renewREQ} );

		$ret =  $self->{req};
		return $ret;
	} else {
		return if ( not $self->{txtREQ} );
		return $self->{txtREQ};
	}
}

sub getPEM {
	my $self = shift;
	my $ret;

	return if( $self->{reqFormat} =~ /SPKAC/i );
	return if( $self->{reqFormat} =~ /RENEW|REVOKE/i );
	return if ( not $self->{pemREQ} );

	return $self->{pemREQ};
}

sub getDER {
	my $self = shift;
	my $ret;

	return if( $self->{reqFormat} =~ /SPKAC/i );
	return if( $self->{reqFormat} =~ /RENEW|REVOKE/i );
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

Sorry, no help available. The REQ module is capable of importing
request like this:

	-----BEGIN HEADER-----
	VAR = NAME
	VAR = NAME
	...
	-----END HEADER-----
	(real request text here)
	-----BEGIN PKCS7-----
	(pkcs#7 signature here
	-----END PKCS7-----

The Real request text can be a request in every form ( DER|PEM ) or
textual (called SPKAC|RENEW|REVOKE datatype). The syntax of the latters
is VAR = NAME on each line (just like the HEADER section).

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::Configuration,
OpenCA::TRIStateCGI, OpenCA::Tools

=cut
