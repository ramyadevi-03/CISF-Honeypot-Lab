# Exercise 4: HTTP and MySQL Honeypot Investigation

## Scenario

The lab monitoring team is investigating activity against a web portal and a
legacy database service on the shared honeypot. Generate one controlled HTTP
request and one dummy MySQL authentication attempt from your assigned Kali
container. Then examine your own OpenCanary evidence and correlate it with
Suricata alerts.

## Objective

Identify your source address, requested web resource, database connection and
authentication attempt, UTC event times, and related Suricata alerts without
exposing credential fields.

## Scope and safety

Only connect from your assigned Kali container to `10.77.0.10`, using HTTP on
port `80` and MySQL on port `3306`. Make one curl request sequence and one
manual dummy database authentication attempt. The HTTP redirect may send more
than one GET within that single curl invocation. Do not query or modify any
database, use SQL, retry credentials, automate attempts, or contact any other
host.

Use only the dummy username and password in this guide. OpenCanary may store
database credentials in its logs; the instructor will show only sanitized
participant-specific evidence. Do not display or share raw log records,
credential fields, or raw protocol transcripts. No Docker or log access is
available inside participant containers.

## Prerequisites

- An instructor-provided terminal in your assigned Kali container.
- Your participant identity and assigned IP address.
- The shared honeypot IP `10.77.0.10`.

If your identity or IP does not match your assignment, stop and ask the
instructor before sending traffic.

## Instructions

### 1. Confirm your assigned identity and source IP

Run:

```bash
hostname
ip -4 -o addr show dev eth0
```

Kali-01 should have address `10.77.0.11`; Kali-02 should have
`10.77.0.12`. Record this as your **source IP**.

### 2. Make one HTTP GET request

The Kali image includes `curl`. Request the web root and follow its redirect:

```bash
curl --verbose --location --max-redirs 3 --max-time 10 --output /dev/null \
  --write-out 'Final HTTP status: %{http_code}; redirects: %{num_redirects}\n' \
  http://10.77.0.10/
```

In the tested lab, this returns final HTTP status `200` after one redirect.
OpenCanary records the GET request; its event may show the redirected resource
`/index.html`, rather than the original `/` URL. Do not treat the HTTP response
code as an authentication result.

### 3. Make one dummy MySQL authentication attempt

The supplied Kali image has no MySQL command-line client. Perl and its
`IO::Socket::INET` module are already installed. Use this small, one-shot
protocol client to read the server greeting, send one MySQL authentication
packet for dummy user `cisf-user` with dummy password `wrong`, and check the
server's response. It connects only to the lab target and performs no SQL:

```bash
perl -MIO::Socket::INET -e '
use strict;
use warnings;
my $socket = IO::Socket::INET->new(
    PeerAddr => "10.77.0.10", PeerPort => 3306, Proto => "tcp", Timeout => 5
) or die "connect failed: $!\n";
$socket->autoflush(1);
sub read_exact {
    my ($sock, $length) = @_;
    my $data = "";
    while (length($data) < $length) {
        my $read = sysread($sock, my $chunk, $length - length($data));
        die "connection closed while reading packet\n"
            unless defined($read) && $read > 0;
        $data .= $chunk;
    }
    return $data;
}
sub write_all {
    my ($sock, $data) = @_;
    while (length($data)) {
        my $written = syswrite($sock, $data);
        die "write failed: $!\n" unless defined($written) && $written > 0;
        substr($data, 0, $written, "");
    }
}
my $greeting_header = read_exact($socket, 4);
my $greeting_length = unpack("V", substr($greeting_header, 0, 3) . "\0");
my $greeting = read_exact($socket, $greeting_length);
die "unexpected MySQL greeting\n"
    unless length($greeting) && ord(substr($greeting, 0, 1)) == 10;
print "MySQL server greeting received (protocol v10).\n";
my $payload = pack("V", 0xA285) . pack("V", 0) . pack("C", 33)
    . ("\0" x 23) . "cisf-user\0" . pack("C", 5) . "wrong";
my $packet = substr(pack("V", length($payload)), 0, 3)
    . pack("C", 1) . $payload;
write_all($socket, $packet);
my $response_header = read_exact($socket, 4);
my $response_length = unpack("V", substr($response_header, 0, 3) . "\0");
my $response = read_exact($socket, $response_length);
die "unexpected MySQL authentication response\n"
    unless ord(substr($response, 0, 1)) == 255;
my $error_code = unpack("v", substr($response, 1, 2));
die "unexpected MySQL error code $error_code\n" unless $error_code == 1045;
print "Dummy authentication rejected (MySQL error 1045, access denied); no login established.\n";
'
```

This confirms the server greeting and the rejected dummy authentication
response. It is not a successful login and does not issue SQL. Do not change
the target, username, password, or packet into a repeated-attempt tool.

### 4. Review your assigned evidence

The instructor will provide only the records filtered for your assigned source
IP and exercise time.

OpenCanary JSON fields observed in this lab:

- Common endpoint/time fields: `utc_time`, `logtype`, `src_host`,
  `src_port`, `dst_host`, `dst_port`, and `node_id`.
- HTTP GET, `logtype` 3000: `logdata.HOSTNAME`, `logdata.PATH`,
  `logdata.SKIN`, and `logdata.USERAGENT` were observed.
- MySQL connection, `logtype` 9003: `logdata` was empty (`{}`); this event
  records a connection, not an authentication attempt.
- MySQL authentication attempt, `logtype` 8001: `logdata.USERNAME` was
  observed. The event also contains `logdata.PASSWORD` (encoded by
  OpenCanary); it is deliberately not included in participant evidence.

Suricata EVE alert records have top-level `timestamp`, `src_ip`, `src_port`,
`dest_ip`, and `dest_port`; signature information is under `alert`. SID
`1000005` detects HTTP GET requests and SID `1000006` detects TCP payload to
the MySQL port. These network detections do not carry OpenCanary's full request
or authentication metadata. MySQL SID `1000006` may alert on multiple packets
in one exchange; multiple alerts do not necessarily mean multiple login
attempts.

### 5. Answer the investigation questions

Use your command output and only your assigned filtered evidence:

1. What source IP initiated your HTTP and MySQL activity, and what target IP
   and destination ports were used?
2. Which HTTP resource appears in OpenCanary's event? How does it relate to
   the URL you requested and the redirect?
3. Which OpenCanary event indicates a MySQL connection, and which indicates
   an authentication attempt? What username is recorded, and does either
   event prove a successful database login?
4. What UTC timestamps identify your HTTP and MySQL events? Which source port
   helps match each log source?
5. Which Suricata signatures correspond to the HTTP and MySQL activity? How
   do you correlate their endpoint fields and timestamps with OpenCanary, and
   what details are not present in the Suricata alerts?

## Expected observations

- Your source address is `10.77.0.11` (Kali-01) or `10.77.0.12` (Kali-02).
- The HTTP request follows one redirect and returns final status `200`. The
  observed OpenCanary GET event has `logtype` 3000 and may record
  `/index.html` in `logdata.PATH`.
- OpenCanary MySQL type 9003 records the connection and has empty `logdata`.
  Type 8001 records the authentication attempt and the username. Neither
  event is proof of successful authentication. The tested service explicitly
  returned MySQL error 1045 (access denied).
- Suricata SID 1000005 alerts on HTTP GET; SID 1000006 alerts on MySQL
  payload traffic. Group repeated alerts by source/destination endpoints,
  client source port, and timestamp.
- OpenCanary and Suricata record the participants' actual source IPs.

## Troubleshooting

- **Unexpected source IP:** Stop and ask the instructor to verify your
  assignment.
- **HTTP error or no response:** Confirm the target and use the exact root URL.
  Following the redirect is expected. Do not probe other hosts or paths.
- **MySQL client unavailable:** This is expected. Use the preinstalled Perl
  protocol command above; do not install packages or use a general-purpose
  database client against other targets.
- **MySQL error 1045:** This is the expected rejection of the dummy login; no
  database login succeeded. Do not retry.
- **Unexpected MySQL response:** Stop and ask the instructor to review the
  service. Do not repeat the authentication attempt.
- **Logs not yet available:** Ask the instructor to check your assigned IP
  and exercise start time and allow up to 30 seconds for records to appear.
- **Credential fields visible:** Do not distribute raw events. Ask the
  instructor for the sanitized, participant-specific evidence.
