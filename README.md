# Orion
A DNS resolver written in C.

Orion, named so after the Great Hunter in the sky, because when you're using Orion you are hunting for information.
It's the first serious project I worked on. I was inspired by "dig", which is built-in on my Ubuntu distribution (16.04).

At this point in time (Thu, 10th Jan 2018, 20:42), it is incomplete.

What Orion can do at this point in time:

1. Get IPv4 and IPv6 addresses of a domain name.
2. Get a name from an IPv4 address, using the in-addr.arpa domain.
3. Get a text record for a domain name.
4. Get mail-exchange record(s).
5. Get zone authority information (Start Of Authority resource record).
6. Get name server information on a domain name.

That leaves a great deal of functionality to add.
