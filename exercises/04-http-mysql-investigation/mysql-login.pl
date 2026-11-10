#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;

my $socket = IO::Socket::INET->new(
    PeerAddr => '10.77.0.10',
    PeerPort => 3306,
    Proto    => 'tcp',
    Timeout  => 5,
) or die "Could not connect to OpenCanary MySQL at 10.77.0.10:3306: $!\n";
$socket->autoflush(1);

sub read_exact {
    my ($length) = @_;
    my $data = '';
    while (length($data) < $length) {
        my $count = sysread($socket, my $chunk, $length - length($data));
        die "MySQL closed the connection before replying.\n"
            unless defined($count) && $count > 0;
        $data .= $chunk;
    }
    return $data;
}

sub write_all {
    my ($data) = @_;
    while (length($data)) {
        my $count = syswrite($socket, $data);
        die "Could not send the MySQL authentication packet.\n"
            unless defined($count) && $count > 0;
        substr($data, 0, $count, '');
    }
}

my $greeting_header = read_exact(4);
my $greeting_length = unpack('V', substr($greeting_header, 0, 3) . "\0");
my $greeting = read_exact($greeting_length);
die "Unexpected MySQL server greeting.\n"
    unless length($greeting) && ord(substr($greeting, 0, 1)) == 10;

my $payload = pack('V', 0xA285) . pack('V', 0) . pack('C', 33)
    . ("\0" x 23) . "cisf-user\0" . pack('C', 5) . "wrong";
my $packet = substr(pack('V', length($payload)), 0, 3)
    . pack('C', 1) . $payload;
write_all($packet);

my $response_header = read_exact(4);
my $response_length = unpack('V', substr($response_header, 0, 3) . "\0");
my $response = read_exact($response_length);
die "Unexpected MySQL authentication response.\n"
    unless length($response) >= 3 && ord(substr($response, 0, 1)) == 255;

my $error_code = unpack('v', substr($response, 1, 2));
die "MySQL returned error $error_code, not the expected access-denied error 1045.\n"
    unless $error_code == 1045;

print "Dummy MySQL authentication rejected (error 1045, access denied); no login established.\n";
