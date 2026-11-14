#vi:filetype=perl

# testcookie_pow: the client adds a nonce of 1 to 16 hex digits to the signed cookie of testcookie_lifetime,
# so that SHA-256 of the whole cookie value starts with the number of zero bits asked for.
# Seeds and nonces are computed here, outside the module.

use lib 'lib';
use Test::Nginx::Socket;
use Digest::SHA qw(sha256 hmac_sha256);

our $S1 = 'flagmebla-flagmebla-flagmebla-flagmebla';
our $S2 = 'anothersecret-anothersecret-anothersecret';
our $DK = sha256('testcookie decoy' . $S1);

sub signed {
    my ($expiry, $key, $session) = @_;
    my $e = pack('N', $expiry);
    return unpack('H*', $e . substr(hmac_sha256($e . $session, $key), 0, 12));
}

sub zero_bits {
    my ($bits) = unpack('B*', sha256($_[0])) =~ /^(0*)/;
    return length $bits;
}

# the first nonce (printf format $fmt) for which the cookie has exactly $n zero bits
sub nonce_exact {
    my ($seed, $n, $fmt) = @_;
    $fmt //= '%x';
    for (my $i = 0; ; $i++) {
        my $x = sprintf($fmt, $i);
        return $x if zero_bits($seed . $x) == $n;
    }
}

# the first nonce for which the cookie has at least $n zero bits
sub nonce_min {
    my ($seed, $n, $fmt) = @_;
    $fmt //= '%x';
    for (my $i = 0; ; $i++) {
        my $x = sprintf($fmt, $i);
        return $x if zero_bits($seed . $x) >= $n;
    }
}

# the first nonce for which the cookie has fewer than $n zero bits
sub nonce_short {
    my ($seed, $n) = @_;
    for (my $i = 0; ; $i++) {
        my $x = sprintf('%x', $i);
        return $x if zero_bits($seed . $x) < $n;
    }
}

our $SEED = signed(time() + 3600, $S1, '127.0.0.1');
our $N8 = nonce_exact($SEED, 8);
our $N10 = nonce_exact($SEED, 10);
our $N16 = nonce_exact($SEED, 16);

plan tests => repeat_each(1) * 93;
no_long_string();
no_root_location();
$ENV{TEST_NGINX_SERVROOT} = server_root();
run_tests();

__DATA__
=== TEST 1: $testcookie_pow is the work asked of the client, from a number or a variable
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    map $arg_d $pow_bits {
        default 14;
        hard 20;
        none "";
    }
--- config
    location = /n {
        testcookie var;
        testcookie_pow 12;
        return 200 "pow=$testcookie_pow";
    }
    location = /v {
        testcookie var;
        testcookie_pow $pow_bits;
        return 200 "pow=$testcookie_pow";
    }
    location = /o {
        testcookie var;
        return 200 "pow=$testcookie_pow";
    }
--- request eval
["GET /n", "GET /v", "GET /v?d=hard", "GET /v?d=none", "GET /o"]
--- response_body eval
["pow=12", "pow=14", "pow=20", "pow=0", "pow="]

=== TEST 2: the cookie passes with a nonce that does the work, and only then
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        testcookie_pow 10;
        return 200 "ok=$testcookie_ok";
    }
--- request eval
["GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N10",
 "Cookie: BPC=$main::SEED",
 "Cookie: BPC=$main::SEED" . main::nonce_short($main::SEED, 10),
 "Cookie: BPC=$main::SEED" . main::nonce_min($main::SEED, 10, 'z%x'),
 "Cookie: BPC=$main::SEED" . main::nonce_min($main::SEED, 10, '%016x'),
 "Cookie: BPC=$main::SEED" . main::nonce_min($main::SEED, 10, '%017x'),
 "Cookie: BPC=" . uc($main::SEED) . main::nonce_min(uc($main::SEED), 10, '%X'),
 "Cookie: BPC=" . main::signed(time() + 3600, $main::S2, '127.0.0.1')
     . main::nonce_min(main::signed(time() + 3600, $main::S2, '127.0.0.1'), 10),
 "Cookie: BPC=" . main::signed(time() - 60, $main::S1, '127.0.0.1')
     . main::nonce_min(main::signed(time() - 60, $main::S1, '127.0.0.1'), 10),
 "Cookie: BPC=" . main::signed(time() + 3600, $main::S1, '10.0.0.1')
     . main::nonce_min(main::signed(time() + 3600, $main::S1, '10.0.0.1'), 10)]
--- response_body eval
["ok=1", "ok=0", "ok=0", "ok=0", "ok=1", "ok=0", "ok=1", "ok=0", "ok=0", "ok=0"]

=== TEST 3: the work is counted in bits, across the bytes of the hash
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        testcookie_pow $arg_bits;
        return 200 "ok=$testcookie_ok";
    }
--- request eval
["GET /t?bits=9", "GET /t?bits=10", "GET /t?bits=11",
 "GET /t?bits=7", "GET /t?bits=8", "GET /t?bits=9",
 "GET /t?bits=16", "GET /t?bits=17",
 "GET /t?bits=0", "GET /t"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N10", "Cookie: BPC=$main::SEED$main::N10", "Cookie: BPC=$main::SEED$main::N10",
 "Cookie: BPC=$main::SEED$main::N8", "Cookie: BPC=$main::SEED$main::N8", "Cookie: BPC=$main::SEED$main::N8",
 "Cookie: BPC=$main::SEED$main::N16", "Cookie: BPC=$main::SEED$main::N16",
 "Cookie: BPC=$main::SEED", "Cookie: BPC=$main::SEED"]
--- response_body eval
["ok=1", "ok=1", "ok=0",
 "ok=1", "ok=1", "ok=0",
 "ok=1", "ok=0",
 "ok=1", "ok=1"]

=== TEST 4: the challenge page carries the seed and the work, and sets no cookie itself
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow 12;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'seed=$testcookie_set pow=$testcookie_pow';
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- error_code: 200
--- response_headers
!Set-Cookie
--- response_body_like: ^seed=[0-9a-f]{32} pow=12$

=== TEST 5: a client that did the work gets the page it asked for
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow 10;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'challenge';
--- config
    location / {
        testcookie on;
    }
--- request eval
["GET /", "GET /"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N10", "Cookie: BPC=$main::SEED"]
--- response_body_like eval
["It works!", "^challenge\$"]

=== TEST 6: a value that is not a number of bits is an error, not a pass
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow $arg_bits;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'challenge';
--- config
    location / {
        testcookie on;
    }
--- request eval
["GET /?bits=33", "GET /?bits=abc", "GET /?bits=-1"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N16", "Cookie: BPC=$main::SEED$main::N16", "Cookie: BPC=$main::SEED$main::N16"]
--- error_code eval
[500, 500, 500]
--- error_log eval
qr/testcookie: invalid testcookie_pow value "(?:33|abc|-1)", it must be 0 to 32/

=== TEST 7: testcookie_pow off in a location turns the inherited one off
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow 20;
--- config
    location = /t {
        testcookie var;
        testcookie_pow off;
        return 200 "ok=$testcookie_ok pow=$testcookie_pow";
    }
--- request
GET /t
--- more_headers eval
"Cookie: BPC=$main::SEED"
--- response_body chomp
ok=1 pow=

=== TEST 8: without testcookie_pow a cookie with a nonce is not a cookie
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        return 200 "ok=$testcookie_ok";
    }
--- request eval
["GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N16", "Cookie: BPC=$main::SEED"]
--- response_body eval
["ok=0", "ok=1"]

=== TEST 9: a seed made with the previous secret passes with the work done
--- http_config
    testcookie_name BPC;
    testcookie_secret anothersecret-anothersecret-anothersecret;
    testcookie_previous_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        testcookie_pow 10;
        return 200 "ok=$testcookie_ok";
    }
--- request eval
["GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=$main::SEED$main::N10", "Cookie: BPC=$main::SEED"]
--- response_body eval
["ok=1", "ok=0"]

=== TEST 10: a decoy is trapped with a nonce, whether or not the nonce does the work
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
--- config
    location = /t {
        testcookie var;
        testcookie_pow 10;
        return 200 "ok=$testcookie_ok trapped=$testcookie_trapped";
    }
--- request eval
["GET /t", "GET /t", "GET /t"]
--- more_headers eval
["Cookie: BPC=" . main::signed(time() + 3600, $main::DK, '127.0.0.1')
     . main::nonce_min(main::signed(time() + 3600, $main::DK, '127.0.0.1'), 10),
 "Cookie: BPC=" . main::signed(time() + 3600, $main::DK, '127.0.0.1')
     . main::nonce_short(main::signed(time() + 3600, $main::DK, '127.0.0.1'), 10),
 "Cookie: BPC=$main::SEED$main::N10"]
--- response_body eval
["ok=0 trapped=1", "ok=0 trapped=1", "ok=1 trapped=0"]

=== TEST 11: a whitelisted client passes without the work
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow 20;
    testcookie_redirect_via_refresh on;
    testcookie_refresh_template 'challenge';
    testcookie_whitelist {
        127.0.0.1/32;
    }
--- config
    location / {
        testcookie on;
    }
--- request
GET /
--- error_code: 200
--- response_body_like: It works!

=== TEST 12: the work needs the signed cookie
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_pow 12;
--- config
    location / {
        testcookie var;
    }
--- must_die
--- error_log
"testcookie_pow" needs "testcookie_lifetime"

=== TEST 13: the work needs a page to do it
--- http_config
    testcookie_name BPC;
    testcookie_secret flagmebla-flagmebla-flagmebla-flagmebla;
    testcookie_session $remote_addr;
    testcookie_lifetime 1h;
    testcookie_pow 12;
--- config
    location / {
        testcookie on;
    }
--- must_die
--- error_log
"testcookie_pow" needs a page that does the work

=== TEST 14: more than 32 bits
--- http_config
    testcookie_pow 33;
--- config
--- must_die
--- error_log
invalid testcookie_pow "33", it must be "off", 0 to 32 or a variable

=== TEST 15: not a number
--- http_config
    testcookie_pow twelve;
--- config
--- must_die
--- error_log
invalid testcookie_pow "twelve"

=== TEST 16: twice on one level
--- http_config
    testcookie_pow 12;
    testcookie_pow 14;
--- config
--- must_die
--- error_log
"testcookie_pow" directive is duplicate

=== TEST 17: with the module off nothing is checked and the variable is empty
--- http_config
    testcookie_name BPC;
    testcookie_pow 12;
--- config
    location = /t {
        testcookie off;
        return 200 "pow=$testcookie_pow";
    }
--- request
GET /t
--- response_body chomp
pow=
