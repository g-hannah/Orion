#include "dns.h"

void
DieSys(const char const *EMsg)
{
	fprintf(stderr, "\e[1;02m\e[3;31m%s - %s\e[m\r\n", EMsg, strerror(errno));
	exit(1);
}

void
Usage(void)
{
	fprintf(stderr, "usage: orion <hostname> [OPTIONS]\r\n"
			"  -D	send DHCP request to find local DNS server(s)\r\n"
			"  -S	specify DNS server [default is 127.0.1.1]\r\n"
			"  -t	specify the type of query:\r\n"
			"		A	IPv4 address\r\n"
			"		AAAA	IPv6 address\r\n"
			"		PTR	convert IPv4/IPv6 address to name\r\n"
			"		NAPTR	find SIP URI for telephone number\r\n"
			"		MX	mail exchange information\r\n"
			"		TXT	server text file information\r\n"
			"		SOA	zone authority information\r\n"
			"		NS	name server information\r\n"
			"		AXFR	request transfer of zone information\r\n"
			"  -x	accept resource records with stale time-to-live\r\n"
			"\r\n"
			"\r\n"
			"Examples:\r\n"
			"\r\n"
			"orion example.com -t AAAA -S 8.8.8.8\r\n"
			"	finds IPv6 address for \"example.com\"\r\n"
			"	using Google's DNS server at 8.8.8.8#53\r\n"
			"\r\n"
			"orion +447123456789 -t NAPTR\r\n"
			"	finds SIP URI for +447123456789\r\n"
			"	using default DNS resolver at 127.0.1.1#53\r\n"
			"\r\n"
			"orion example.com -t AAAA -D\r\n"
			"	finds IPv6 address for \"example.com\"\r\n"
			"	using DNS server found via DHCP request\r\n"
			"\r\n"
			"orion example.com -t NS -x\r\n"
			"	finds name server for \"example.com\" and\r\n"
			"	accepts records with stale time-to-live values\r\n");
	exit(1);
}

