#!/usr/bin/env perl
use strict;
use warnings;
use IO::Socket::INET;
use IO::Select;

my $socket = IO::Socket::INET->new(
    PeerAddr => '10.77.0.10',
    PeerPort => 2223,
    Proto    => 'tcp',
    Timeout  => 5,
) or die "Could not connect to Cowrie Telnet at 10.77.0.10:2223: $!\n";
$socket->autoflush(1);
my $ready = IO::Select->new($socket);
my ($state, $verb) = (0, 0);
my ($received, $username_sent, $password_sent) = ('', 0, 0);
my %replied;
my $deadline = time + 20;

sub write_all {
    my ($data) = @_;
    while (length($data)) {
        my $count = syswrite($socket, $data);
        die "Telnet connection closed while negotiating or sending login data.\n"
            unless defined($count) && $count > 0;
        substr($data, 0, $count, '');
    }
}

while (time < $deadline) {
    next unless $ready->can_read(1);

    my $count = sysread($socket, my $buffer, 4096);
    die "Telnet connection closed before authentication completed.\n"
        unless defined($count) && $count > 0;

    for my $byte (unpack('C*', $buffer)) {
        if ($state == 0) {
            if ($byte == 255) {
                $state = 1;
            } else {
                $received .= chr($byte);
                substr($received, 0, length($received) - 512, '')
                    if length($received) > 512;
            }
        } elsif ($state == 1) {
            if ($byte == 255) {
                $received .= chr(255);
                $state = 0;
            } elsif ($byte == 250) {
                $state = 3;
            } elsif ($byte >= 251 && $byte <= 254) {
                $verb = $byte;
                $state = 2;
            } else {
                $state = 0;
            }
        } elsif ($state == 2) {
            my $key = "$verb:$byte";
            if (!$replied{$key}++) {
                if ($verb == 253) {
                    my $supported = $byte == 0 || $byte == 1 ||
                        $byte == 3 || $byte == 31;
                    write_all(pack('C*', 255, $supported ? 251 : 252, $byte));
                    if ($byte == 31 && $supported) {
                        write_all(pack('C*', 255, 250, 31, 0, 80, 0, 24, 255, 240));
                    }
                } elsif ($verb == 251) {
                    my $supported = $byte == 0 || $byte == 1 || $byte == 3;
                    write_all(pack('C*', 255, $supported ? 253 : 254, $byte));
                } elsif ($verb == 254) {
                    write_all(pack('C*', 255, 252, $byte));
                } elsif ($verb == 252) {
                    write_all(pack('C*', 255, 254, $byte));
                }
            }
            $state = 0;
        } elsif ($state == 3) {
            $state = 4 if $byte == 255;
        } elsif ($state == 4) {
            $state = $byte == 240 ? 0 : 3;
        }

        if (!$username_sent && $received =~ /(?:login|username)\s*:\s*$/i) {
            write_all("cisf-telnet-lab\r\n");
            $username_sent = 1;
            $received = '';
            print "Telnet username prompt received; submitted the exercise username.\n";
        } elsif ($username_sent && !$password_sent &&
                 $received =~ /password\s*:\s*$/i) {
            write_all("CISF-Dummy-Password-2026\r\n");
            $password_sent = 1;
            print "Telnet password prompt received; submitted one dummy login attempt.\n";
            last;
        }
    }

    last if $password_sent;
}

die "Timed out waiting for the Telnet login prompt.\n" unless $username_sent;
die "Timed out waiting for the Telnet password prompt.\n" unless $password_sent;
select undef, undef, undef, 0.25;
close $socket;
print "Connection closed. Cowrie's recorded login outcome is simulated.\n";
