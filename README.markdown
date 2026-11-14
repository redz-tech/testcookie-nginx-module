Description
===========

**testcookie-nginx-module** is a simple robot mitigation module using cookie based challenge/response.

Challenge cookies can be set using different methods:

*   "Set-Cookie" + 302/307 HTTP Location redirect
*   "Set-Cookie" + HTML meta refresh redirect
*   Custom template, JavaScript can be used here.

The challenge cookie value can be encrypted with AES-128 in CBC mode using custom/random key and iv, and then decrypted at client side with JavaScript, so that a client has to run a script to get it. This does not stop a client that parses the page: the key, the iv and the encrypted value are all in it (see below).

What it stops and what it does not
==================================

The check runs in the access phase, before any backend, and costs almost nothing. It stops clients that do not keep cookies, and - with a JavaScript template - clients that do not run JavaScript: most flood scripts and scanners.

It does not stop:

*   **A script written for the challenge.** Everything needed to compute the cookie is in the answer: the cookie itself in Set-Cookie, or the key, iv and encrypted value in the page with *testcookie_refresh_encrypt_cookie*. Solvers for the common AES template are public. On a production site under a login brute force we saw a script send each challenged request again, with a valid cookie, within a second, without loading the page's script.
*   **A real browser**, headless or not: it passes any JavaScript challenge.
*   **Anything after the first pass.** The cookie is md5(*testcookie_session* + *testcookie_secret*): it has no expiry of its own, so once solved for a session value (by default the client's address) it stays valid until the secret changes. Changing the secret revokes every cookie at once.

So use it to cut cheap traffic in front of the backend, and limit what a client that passed may do - request rates, login attempts - by other means.

Common pitfalls
===============

*   **The script that solves the challenge must not be challenged.** If the challenge is on at a level that also covers the location serving the AES script (or any other file the template loads), add *testcookie off* there, or no browser can pass.
*   **An *if* at server level does not switch the challenge off for a location**: the location's own setting wins. Use *testcookie_pass* with a *map*, or an *if* inside the location.
*   **testcookie_get_only off challenges POST too.** A browser follows the challenge with GET, so the POST body is lost; use it where a client gets a GET page first (a login form, for example).
*   **testcookie_deny_keepalive works on HTTP/1.x only**; on HTTP/2 and HTTP/3 it does nothing.
*   **Not on port 80 or 443**: set *testcookie_port_in_redirect on*, or the redirect drops the port.
*   **Behind a proxy or CDN** *$remote_addr* is the proxy's address unless the real IP module is set up, and every client shares one cookie.
*   **nginx 1.29.6 changed how Cookie headers are parsed.** The module picks its parser at compile time, so with nginx 1.29.6 or later build a module version that has #83/#84 (May 2026). An older module builds against the new nginx without a warning and then redirects in a loop whenever another cookie comes before the challenge cookie in the request.


Directives
==========

testcookie
----------
**syntax:** *testcookie (on|off|var);*

**default:** *off*

**context:** *http, server, location, if*

on - Enable module

off - Disable module

var - Don't intercept requests, only set module variables.


testcookie_name
---------------
**syntax:** *testcookie_name &lt;string&gt;*

**default:** *TCK*

**context:** *http, server, location*

Sets cookie name.

testcookie_domain
-----------------
**syntax:** *testcookie_domain &lt;string&gt;*

**default:** *none, set by browser*

**context:** *http, server, location*

Sets cookie domain.


testcookie_expires
------------------
**syntax:** *testcookie_expires &lt;string&gt;*

**default:** *none, a session cookie*

**context:** *http, server, location*

Sets cookie expiration value: a time (for example *10d*) or *max* (31 Dec 2037 23:55:55 GMT). Without it the cookie lasts until the browser is closed.

testcookie_path
---------------
**syntax:** *testcookie_path &lt;string&gt;*

**default:** */*

**context:** *http, server, location*

Sets cookie path, useful if you plan to use different keys for locations.

testcookie_samesite
---------------
**syntax:** *testcookie_samesite &lt;string&gt;*

**default:** *None*

**context:** *http, server, location*

Sets cookie attribute, allows you to declare if your cookie should be restricted to a first-party or same-site context.
Default is None (Cookies will be sent in all contexts, i.e sending cross-origin is allowed.)
Accepts values: Lax, Strict, None.

testcookie_secret
-----------------
**syntax:** *testcookie_secret &lt;string&gt;*

**default:** *required configuration directive*

**context:** *http, server, location*

Secret string, used in challenge cookie computation, should be 32 bytes or more,
better to be long but static to prevent cookie reset for legitimate users every server restart.
If set to *"random"* - new secret will be generated every server restart, not recomended(all cookies with previous key will be invalid),

testcookie_previous_secret
--------------------------
**syntax:** *testcookie_previous_secret &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

A cookie that does not match *testcookie_secret* is checked against this secret too. It lets you change the secret
without challenging every client again: put the old secret here, the new one in *testcookie_secret*, reload nginx.
New cookies are always made with *testcookie_secret*. Should be 32 bytes or more, cannot be *random*.

With *testcookie_lifetime* the old secret can go one lifetime after the change, when every cookie made with it has
expired. Without a lifetime cookies never expire, and the old secret keeps them passing for as long as it stays here.

testcookie_lifetime
-------------------
**syntax:** *testcookie_lifetime &lt;time&gt;|off*

**default:** *off*

**context:** *http, server, location*

How long a cookie passes. With a lifetime the cookie carries its own expiry and is signed: 4 bytes of expiry time
followed by the first 12 bytes of HMAC-SHA256(secret, expiry | session). It is still 32 hex digits, so templates,
*$testcookie_set*, *$testcookie_enc_set* and the AES page work as they did. Without a lifetime (the default) the cookie
is md5(session | secret) and passes for as long as the secret and the session stay the same.

* A client is challenged again when its cookie expires. Every cookie expires one lifetime after its own challenge, so
  clients are not all challenged again at the same moment.
* A request that passes does not extend the cookie: a browser sees the challenge once per lifetime.
* The expiry is checked against the server clock: servers behind one balancer need the same secret and close clocks.
* A cookie passes until the expiry it carries, so a shorter lifetime applies to new cookies. To end the old ones at
  once, change the secret (without *testcookie_previous_secret*).
* Turning the lifetime on or off challenges every client once: the two kinds of cookie do not pass for each other.
* *testcookie_expires* still only tells the browser how long to keep the cookie. Make it at least the lifetime, or
  leave it a session cookie.
* Needs *testcookie_secret*.
* Costs about as much as the md5 cookie: the HMAC key is prepared when nginx reads its configuration.

It stops a cookie from one solved challenge being used for days or months. It does not stop a script that solves the
challenge again after the cookie expires.

Decoy: $testcookie_decoy, $testcookie_enc_decoy, $testcookie_trapped
--------------------------------------------------------------------
A script that solves the challenge without running the page reads the values out of it by pattern. The decoy is a
second value that looks like the cookie, for the page to carry where a browser never runs it and such a script finds it
first. A browser never sends the decoy back: a client that does has read the page without running it.

    $testcookie_decoy     - the decoy, 32 hex digits, like $testcookie_set
    $testcookie_enc_decoy - the decoy encrypted with the key and iv of the page, like $testcookie_enc_set
    $testcookie_trapped   - 1 if the client sent the decoy back as its cookie, 0 otherwise

The decoy comes from *testcookie_secret* with a key of its own, so it cannot be told from the cookie without the
secret. It is fixed for a session like the md5 cookie; with *testcookie_lifetime* it carries the expiry of the real
cookie and changes with it. A decoy is trapped even after its expiry. There is no decoy without *testcookie_secret*,
for a whitelisted client, or with the module off. The variables cost nothing when they are not used.

A client that sends the decoy is challenged again like any client without a valid cookie. What else happens is up to
the configuration, for example:

    location / {
        testcookie on;
        if ($testcookie_trapped = 1) {
            return 444;
        }
    }

    access_log /var/log/nginx/trapped.log combined if=$testcookie_trapped;

Put the decoy before the real values, where the page never uses it: in a comment, in a script that never runs, in a
function that is never called. For the page in the example below, the start of its second script could be:

    <script>/* var a=toNumbers("$testcookie_enc_key"),b=toNumbers("$testcookie_enc_iv"),c=toNumbers("$testcookie_enc_decoy"); */

The decoy catches scripts that take the first match; a script that runs the page in a JavaScript engine, or is adapted
to skip the decoy, is not caught. Change where the decoy sits from time to time.

testcookie_pow
--------------
**syntax:** *testcookie_pow &lt;bits&gt;|&lt;variable&gt;|off*

**default:** *off*

**context:** *http, server, location*

Asks the client for work before its cookie passes (a proof of work). The cookie of *testcookie_lifetime* becomes a
seed: the page looks for a nonce of 1 to 16 hex digits such that SHA-256 of the seed followed by the nonce starts with
*bits* zero bits, and sets the cookie to the seed followed by the nonce. The server checks the nonce with one SHA-256,
then the signature and the expiry as without the work. Nothing is kept on the server.

    $testcookie_pow - the number of bits asked of this client, empty without testcookie_pow

* *bits* is 0 to 32: every bit doubles the work. 0, or an empty value, asks for none and the seed alone passes.
* A variable sets the work per request, for example more for some networks:

        geo $pow_bits {
            default        16;
            203.0.113.0/24 20;
        }
        testcookie_pow $pow_bits;

  Any other value is an error: the client gets 500 and the error log says which value. The work is checked when the
  cookie comes back, against the work asked at that moment: when it goes up, cookies that did less are challenged again.
* Needs *testcookie_lifetime*, and with *testcookie on* a page that does the work: *testcookie_redirect_via_refresh on*
  and *testcookie_refresh_template*. No Set-Cookie is sent: the page sets the cookie.
* Without *testcookie_pow* a cookie with a nonce does not pass, as before.
* A decoy sent with a nonce is still trapped.
* Costs one SHA-256 of at most 48 bytes per request with a cookie: on the bench, within the noise of the measurement.

[doc/pow.html](doc/pow.html) is a page that does the work, for *testcookie_refresh_template_file* (#93); without it the
page has to go into *testcookie_refresh_template* as one string. It uses *$testcookie_set*, *$testcookie_pow* and
*$testcookie_nexturl*, and sets the cookie BPC: write your *testcookie_name* in it. It looks for the nonce in up to
four Web Workers, with SHA-256 written in JavaScript (*crypto.subtle* is only there on https), and in the page itself,
by slices, where workers are not allowed.

What it costs a client, measured on one laptop (Apple M-series, 10 cores):

* The page's SHA-256 runs at 3.5 million hashes a second in one thread of V8 at normal priority. Headless Chrome runs
  its pages at background priority, where it was 0.9 million a worker.
* The work is 2^bits hashes on average, but it is luck: half the clients need less than 0.7 of the average, one in
  twenty more than 3 times it. At 14 million hashes a second (four workers at normal priority) the average is 5 ms for
  16 bits, 19 ms for 18, 75 ms for 20, 0.3 s for 22 and 1.2 s for 24 (computed).
* Headless Chrome on the stand, from the challenge page to the page behind it, 20 runs each: median 35 ms at 16 bits,
  78 ms at 18, 222 ms at 20, 1.1 s at 22 (the slowest 5.3 s); 2.4 s at 24 (10 runs, the slowest 12.4 s).
* Firefox 160 (headless) and WebKit (the WKWebView of macOS) pass too, at 18 bits, 10 runs each: Firefox median
  42 ms over HTTP/1.1 and 65 ms over HTTP/2, WebKit 26 ms over HTTP/2.
* Phones were not measured; their cores are slower.

What it stops and what it does not:

* It is a price per pass, not per request: a cookie that did the work passes for its session until it expires.
* A script that does the work itself passes. It pays CPU time for every session: natively the hash is only a few times
  faster than the page (OpenSSL: 10.8 million a second on one core of the same laptop; a Python script: 2.4 million,
  135 ms of one core a pass at 18 bits), and a GPU is much faster still. It makes many new sessions expensive, such as a
  botnet or rotating addresses where *testcookie_session* has the address; a few sessions that send many requests pay
  once per lifetime, so use *limit_req* for those.
* The more work, the longer a real visitor waits on a slow device: start low (16-18 bits) and raise it with a variable
  where it is needed.

testcookie_session
------------------
**syntax:** *testcookie_session &lt;variable&gt;*

**default:** *required configuration directive*

**context:** *http, server, location*

Sets the challenge generation function input,
*   $remote_addr - clients IP address will be used as an user unique identifier
*   $remote_addr$http_user_agent - clients IP + User-Agent

testcookie_arg
--------------
**syntax:** *testcookie_arg &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Sets GET parameter name, used for cookie setting attempts computation,

If not set - server will try to set cookie infinitely.

testcookie_max_attempts
-----------------------
**syntax:** *testcookie_max_attempts &lt;integer&gt;*

**default:** *4*

**context:** *http, server, location*

Sets maximum number of redirects before user will be sent to fallback URL (or gets 403 without one). RFC1945 allows up to 5 redirects, so it can't be more than 4.

If set to 0 - server will try to set cookie infinitely(actually, browser will show the error page).


testcookie_p3p
--------------
**syntax:** *testcookie_p3p &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Sets P3P policy.

testcookie_fallback
-------------------
**syntax:** *testcookie_fallback &lt;script&gt;*

**default:** *none*

**context:** *http, server, location*

Sets the fallback URL, user will be redirected to after maximum number of attempts, specified by directive *testcookie_max_attempts* exceded.
Nginx scripting variables can be used here. If not set - client will get 403 after max attempts reached.

testcookie_whitelist
--------------------
**syntax:** *testcookie_whitelist &lt;network list&gt;*

**default:** *none*

**context:** *http, server*

Sets the networks for which the testing will not be used, add search engine networks here. IPv4 and IPv6 CIDR; an address without a mask is that one address (/32 or /128), not its network.

testcookie_pass
---------------
**syntax:** *testcookie_pass $variable;*

**default:** *none*

**context:** *http, server*

Sets the variable name to test if cookie check should be bypassed.
If variable value set to *1* during the request - cookie check will not be performed.
Can be used for more complex whitelisting.

testcookie_redirect_via_refresh
-------------------------------
**syntax:** *testcookie_redirect_via_refresh (on|off);*

**default:** *off*

**context:** *http, server, location*

Set cookie and redirect using HTTP meta refresh, required if *testcookie_refresh_template* used.

testcookie_refresh_template
---------------------------
**syntax:** *testcookie_refresh_template &lt;string&gt;*

**default:** *none*

**context:** *http, server, location*

Use custom html instead of simple HTTP meta refresh, you need to set cookie manually from the template
Available all the nginx variables and

    $testcookie_nexturl - URL the client should be redirected to, if max_attempts exceeded *testcookie_fallback* value will be here
    $testcookie_got - cookie value received from client, empty if no cookie or it does not match format
    $testcookie_set - correct cookie value we're expecting from client
    $testcookie_ok - user passed test (1 - passed, 0 - not passed) Note: changed from "yes"/"no" in v1.10

also, if testcookie_refresh_encrypt_cookie enabled there are three more variables:

    $testcookie_enc_key - encryption key (32 hex digits)
    $testcookie_enc_iv - encryption iv (32 hex digits)
    $testcookie_enc_set - encrypted cookie value (32 hex digits)

testcookie_refresh_status
-------------------------
**syntax:** *testcookie_refresh_status &lt;code&gt;*

**default:** *200*

**context:** *http, server, location*

Use custom HTTP status code when serving html.

testcookie_refresh_template_file
--------------------------------
**syntax:** *testcookie_refresh_template_file &lt;path&gt;*

**default:** *none*

**context:** *http, server, location*

The same as *testcookie_refresh_template*, with the page read from a file instead of written in one line of the
configuration. A relative path is taken from the directory of nginx.conf, like *include*. The file is read when nginx
reads its configuration: after changing the page, reload nginx.

The page has the same variables, and a level has either the string or the file, not both. A nested level may set its
own string or file, and *testcookie_refresh_template none* there brings back the default meta refresh page.

nginx has no escape for the dollar sign: every *$* in the file starts a variable, and an unknown or broken name stops
nginx from loading the configuration. If the page needs a literal *$* (jQuery, template strings), define a variable
that holds one and write *${dollar}* in the page:

    geo $dollar {
        default "$";
    }

A working page for the encrypted cookie is in [doc/refresh_template.html](doc/refresh_template.html): it needs
*testcookie_name BPC*, *testcookie_redirect_via_refresh on*, *testcookie_refresh_encrypt_cookie on* and SlowAES served
from */aes.min.js* by a location with *testcookie off*. Writing a page of your own is worth it: a script made to solve
the stock page by pattern does not understand a different one, though it takes little to adapt one to your page.


testcookie_deny_keepalive
-------------------------
**syntax:** *testcookie_deny_keepalive (on|off);*

**default:** *off*

**context:** *http, server, location*

Close connection just after setting the cookie, no reason to keep connections with bots.

testcookie_get_only
-------------------
**syntax:** *testcookie_get_only (on|off);*

**default:** *off*

**context:** *http, server, location*

Process only GET requests, POST requests will be bypassed.

testcookie_https_location
-------------------------
**syntax:** *testcookie_https_location (on|off);*

**default:** *off*

**context:** *http, server, location*

Redirect client to https protocol after setting the cookie, also affects *$testcookie_nexturl*, useful with 3dparty SSL offload.

testcookie_refresh_encrypt_cookie
---------------------------------
**syntax:** *testcookie_refresh_encrypt_cookie (on|off);*

**default:** *off*

**context:** *http, server, location*

Encrypt cookie variable, used with *testcookie_refresh_template* to force client-side decryption with AES-128 CBC.

testcookie_refresh_encrypt_cookie_key
-------------------------------------
**syntax:** *testcookie_refresh_encrypt_cookie_key &lt;32 hex digits|random&gt;*

**default:** *required directive if encryption enabled*

**context:** *http, server, location*

Sets encryption key.

Possible values:

    random - new key generated every nginx restart
    32 hex digits - static key, useful if you plan to obfuscate it deep in client-side javascript.

testcookie_refresh_encrypt_iv
-----------------------------
**syntax:** *testcookie_refresh_encrypt_iv &lt;32 hex digits|random|random2&gt;*

**default:** *random*

**context:** *http, server, location*

Sets encryption iv.

Possible values:
    random - new iv generated for every client request
    random2 - new iv generated for every nginx restart
    32 hex digits - static iv, useful if you plan to obfuscate it deep in client-side javascript

testcookie_internal
-------------------
**syntax:** *testcookie_internal (on|off);*

**default:** *off*

**context:** *http, server, location*

Enable testcookie check for internal redirects (disabled by default for optimization purposes!), useful for this type of configs:

    rewrite ^/(.*)$ /index.php?$1 last;

testcookie_httponly_flag
------------------------
**syntax:** *testcookie_httponly_flag (on|off);*

**default:** *off*

**context:** *http, server, location*

Enable HttpOnly flag for cookie.

testcookie_secure_flag
------------------------
**syntax:** *testcookie_secure_flag (on|off|$variable);*

**default:** *on*

**context:** *http, server, location*

Enable Secure flag for cookie.
Any variable value except "on" interpreted as False.

testcookie_port_in_redirect
---------------------------
**syntax:** *testcookie_port_in_redirect (on|off);*

**default:** *off*

**context:** *http, server, location*

Expose port in redirect.


Installation
============

Grab the nginx source code from [nginx.org](http://nginx.org/), for example, the version 1.1.15 (see nginx compatibility), and then build the source with this module:

    wget 'http://nginx.org/download/nginx-1.1.15.tar.gz'
    tar -xzvf nginx-1.1.15.tar.gz
    cd nginx-1.1.15/
    ./configure --add-module=/path/to/testcookie-nginx-module

    make
    make install

If you use nginx >= 1.9.11 you can compile Dynamic module.

    wget 'http://nginx.org/download/nginx-1.9.11.tar.gz'
    tar -xzvf nginx-1.9.11.tar.gz
    cd nginx-1.9.11/
    ./configure --add-dynamic-module=/path/to/testcookie-nginx-module

    make
    make install

Then load "ngx_http_testcookie_access_module.so" using "load_module" directive.

For using client-side cookie decryption, you need to manually grab [SlowAES](http://code.google.com/p/slowaes/) JavaScript AES implementation,
**patch it(utils/aes.patch)** and put it to document root.

Compatibility
=============

Module was tested with nginx 1.1+, but should work with 1.0+. The test suite passes with nginx 1.22.1, 1.26.3, 1.28.3, 1.30.6 and 1.31.8, over HTTP/1.1, HTTP/2 and HTTP/3 alike (see the pitfall about nginx 1.29.6 above).

Example configuration
=====================

    http {
        #default config, module disabled
        testcookie off;

        #setting cookie name
        testcookie_name BPC;

        #setting secret
        testcookie_secret keepmesecret;

        #setting session key
        testcookie_session $remote_addr;

        #setting argument name
        testcookie_arg ckattempt;

        #setting maximum number of cookie setting attempts
        testcookie_max_attempts 3;

        #setting p3p policy
        testcookie_p3p 'CP="CUR ADM OUR NOR STA NID", policyref="/w3c/p3p.xml"';

        #setting fallback url
        testcookie_fallback http://google.com/cookies.html?backurl=http://$host$request_uri;

        #configuring whitelist
        testcookie_whitelist {
            8.8.8.8/32;
        }


        #setting redirect via html code
        testcookie_redirect_via_refresh on;

        #enable encryption
        testcookie_refresh_encrypt_cookie on;

        #setting encryption key
        testcookie_refresh_encrypt_cookie_key deadbeefdeadbeefdeadbeefdeadbeef;

        #setting encryption iv
        testcookie_refresh_encrypt_cookie_iv deadbeefdeadbeefdeadbeefdeadbeef;

        #setting response template
        testcookie_refresh_template '<html><body>setting cookie...<script type=\"text/javascript\" src=\"/aes.min.js\" ></script><script>function toNumbers(d){var e=[];d.replace(/(..)/g,function(d){e.push(parseInt(d,16))});return e}function toHex(){for(var d=[],d=1==arguments.length&&arguments[0].constructor==Array?arguments[0]:arguments,e="",f=0;f<d.length;f++)e+=(16>d[f]?"0":"")+d[f].toString(16);return e.toLowerCase()}var a=toNumbers("$testcookie_enc_key"),b=toNumbers("$testcookie_enc_iv"),c=toNumbers("$testcookie_enc_set");document.cookie="BPC="+toHex(slowAES.decrypt(c,2,a,b))+"; expires=Thu, 31-Dec-37 23:55:55 GMT; path=/";location.href="$testcookie_nexturl";</script></body></html>';

        server {
            listen 80;
            server_name test.com;


            location = /aes.min.js {
                gzip  on;
                gzip_min_length 1000;
                gzip_types      text/plain;
                root /var/www/public_html;
            }

            location = /w3c/p3p.xml {
                root /var/www/public_html;
            }
            
            # required for passing Let's Encrypt ACME challenge, remove if not required
            location = /.well-known/acme-challenge/ {
                root /var/www/public_html;
            }


            location / {
                #enable module for specific location
                testcookie on;
                proxy_set_header   Host             $host;
                proxy_set_header   X-Real-IP        $remote_addr;
                proxy_set_header   X-Forwarded-For  $proxy_add_x_forwarded_for;
                proxy_pass http://127.0.0.1:80;
            }
        }
    }

See more cases in "docs" directory of the project.

Test suite
===========

This module comes with a Perl-driven test suite. Thanks to the [Test::Nginx](http://search.cpan.org/perldoc?Test::Nginx) module in the Perl world.

Build nginx with the module, install Test::Nginx (`cpanm Test::Nginx`) and run

    TEST_NGINX_BINARY=/path/to/objs/nginx prove -r t/

For memory errors build nginx with `--with-cc-opt='-fsanitize=address -DNGX_DEBUG_PALLOC=1' --with-ld-opt=-fsanitize=address`: without `NGX_DEBUG_PALLOC` an overrun inside an nginx pool goes unnoticed.

Sources
=======

Available on github at [kyprizel/testcookie-nginx-module](http://github.com/kyprizel/testcookie-nginx-module).

TODO
====

*   Code review
*   Statistics (?)

Bugs
====

Feel free to report bugs and send patches to kyprizel@gmail.com
or using [github's issue tracker](http://github.com/kyprizel/testcookie-nginx-module/issues).

Support the project
===================

    Send your donations to 1FHmPTP6aDBAzVtM7Pe7Y69zqhjPRx847s


Copyright & License
===================

Copyright (C) 2011-2017 Eldar Zaitov (kyprizel@gmail.com).

All rights reserved.

This module is licenced under the terms of BSD license.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

    *   Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
    *   Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
    *   Neither the name of the authors nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
SUCH DAMAGE.
