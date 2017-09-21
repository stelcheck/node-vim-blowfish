#!/usr/bin/perl

# This script performs Vim-compatible encryption and decryption of files
# using Blowfish algorithm. 'Vim-compatible' means that you can use this
# script to decrypt files encrypted with Vim and vice versa.

# Author: Yuri Volkov (mail@yuri-volkov.com)

# August 2012


use Digest::SHA sha256_hex;
use Crypt::Blowfish;

if ( @ARGV != 2 )
{
    $0 =~ s/.*\///;
    die "Usage: $0 <filename> <password>\n";
}

die "File '$ARGV[0]' not found\n" if not -e $ARGV[0];


# Read file into $buffer

open FILE, '<', $ARGV[0]
    or die "Could not open file $ARGV[0] for reading\n";

binmode FILE;

$buffer = '';

while ( read(FILE, $buffer, 4096, length($buffer)) ) { }

close FILE;


# Read salt and initialization vector (IV) from the file header
# or generate new salt and IV if the file is not encrypted

if ( $buffer =~ /^VimCrypt~02!.{8}.{8}/s )  # if file is encrypted
{
    $salt = substr($buffer, 12, 8);
    $iv = substr($buffer, 12+8, 8);

    $buffer = substr($buffer, 12+8+8);
}
elsif ( $buffer =~ /^VimCrypt~01!/ )
{
    die "This script decrypts only Blowfish-encrypted files. Did you forget ':set cryptmethod=blowfish'?\n";
}
else
{
    # Generate random Salt and IV

    for ( $i = 0; $i < 8; $i++ )
    {
        $salt .= pack('C', int(rand(255)));
        $iv   .= pack('C', int(rand(255)));
    }

    $flag = 1;  # 1 - encrypt file; 0 - decrypt file
}

print "salt: " . unpack('H*', $salt) . "\n";
print "  iv: " . unpack('H*', $iv) . "\n";
print "\n";


# Generate encryption key

$key = sha256_hex($ARGV[1] . $salt);

for ( $i = 0; $i < 1000; $i++ )
{
	if ($i < 5) {
        print " key: $key\n";
    }

    $key = sha256_hex($key . $salt);
}

print "\n key: $key\n";

$key = pack('H*', $key);


# Initialize Cipher feedback (CFB) keystream

$keystream = &encrypt($iv x 8, $key);


# Encrypt or decrypt $buffer using Blowfish algorithm in Cipher Feedback (CFB) mode

open FILE, '>', $ARGV[0] . '.decrypted'
    or die "Could not open file $ARGV[0] for writing\n";

binmode FILE;

print FILE "VimCrypt~02!$salt$iv" if $flag;

for ($i = 0; $i < length($buffer); $i += 64)
{
    $text = substr($buffer, $i, 64);

    print FILE $text ^ substr($keystream, 0, length($text));

    # Update keystream for encryption or decryption of the next 64-byte block

    if ( length($text) == 64 )
    {
        $keystream = &encrypt($flag ? $text ^ $keystream : $text, $key);
    }
}

close FILE;

print "\n" . length($buffer) . " bytes " . ( $flag ? "encrypted" : "decrypted" ) . "\n\n";

exit(0);


# Function encrypt() arguments:
#
# 1) $_[0] - 64 bytes long string of plaintext
# 2) $_[1] - encryption key

sub encrypt()
{
    return undef if length($_[0]) != 64;

    $cipher = new Crypt::Blowfish $_[1] if !defined($cipher);

    my ( @ptext, @ctext, $i );

    @ptext = $_[0] =~ /.{8}/sg;  # split $_[0] into 8 bytes long chunks

    for ( $i = 0; $i < @ptext; $i++ )
    {
        # convert from little-endian unsigned long to big-endian,
        # so that 0x01020304 05060708 becomes 0x04030201 08070605

        print " >> ";
        $ptext[$i] = pack('V*', unpack('N*', $ptext[$i]));
        print $ptext[$i] . "\n";

		# encrypt 8 bytes of plaintext

        $ctext[$i] = $cipher->encrypt($ptext[$i]);

        # convert from big-endian unsigned long to little-endian

        $ctext[$i] = pack('V*', unpack('N*', $ctext[$i]));
    }

    return join('', @ctext);
}
