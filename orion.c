#include "orion.h"
#include "cache.h"

struct options
{
	int tcp;
	int v6;
};

static struct options o;
static int host_max = 0;

/* Caches for different resource records */
static cache_t *answers_cache;
static cache_t *auth_cache;
static cache_t *additional_cache;

static DNS_RRECORD *rrecord_ptr;

static int dns_rrecord_cache_ctor(void *) __nonnull((1)) __wur;
static void dns_rrecord_cache_dtor(void *) __nonnull((1));

static void
__attribute__((constructor)) __orion_init(void)
{
	if ((host_max = sysconf(_SC_HOST_NAME_MAX)) == 0)
		host_max = 1024;

	if (!(answers_cache = cache_create(
			"answer_record_cache",
			0,
			sizeof(DNS_RRECORD),
			dns_rrecord_cache_ctor,
			dns_rrecord_cache_dtor)))
	{
		fprintf(stderr, "__orion_init: failed to create resource record object cache\n");
		goto fail;
	}

	if (!(auth_cache = cache_create(
			"authoratative_record_cache",
			0,
			sizeof(DNS_RRECORD),
			dns_rrecord_cache_ctor,
			dns_rrecord_cache_dtor)))
	{
		fprintf(stderr, "__orion_init: failed to create resource record object cache\n");
		goto fail;
	}

	if (!(additional_cache = cache_create(
			"additional_rrecord_cache",
			0,
			sizeof(DNS_RRECORD),
			dns_rrecord_cache_ctor,
			dns_rrecord_cache_dtor)))
	{
		fprintf(stderr, "__orion_init: failed to create resource record object cache\n");
		goto fail;
	}

	return;

	fail:
	exit(EXIT_FAILURE);
}

static void
__attribute__((destructor)) __orion_fini(void)
{
	cache_clear_all(answers_cache);
	cache_destroy(answers_cache);
	cache_clear_all(auth_cache);
	cache_destroy(auth_cache);
	cache_clear_all(additional_cache);
	cache_destroy(additional_cache);

	return;
}

uc *
get_rcode(unsigned short rcode)
{
	switch(rcode)
	{
		case 0:
			return "\e[1;02m\e[1;32mno error\e[m";
			break;
		case 1:
			return "\e[3;31mformat error\e[m";
			break;
		case 2:
			return "\e[3;31mserver failure\e[m";
			break;
		case 3:
			return "\e[3;31mnon-existent domain\e[m";
			break;
		case 4:
			return "\e[3;31mnot implemented\e[m";
			break;
		case 5:
			return "\e[3;31mquery refused\e[m";
			break;
		case 6:
			return "\e[3;31mname exists but should not\e[m";
			break;
		case 7:
			return "\e[3;31mRRSet exists but should not\e[m";
			break;
		case 8:
			return "\e[3;31mRRSet does not exist but should\e[m";
			break;
		case 9:
			return "\e[3;31mserver not authorised for zone\e[m";
			break;
		case 10:
			return "\e[3;31mname not contained in zone\e[m";
			break;
		case 16:
			return "\e[3;31mbad SIG\e[m";
			break;
		case 17:
			return "\e[3;31mbad key\e[m";
			break;
		case 18:
			return "\e[3;31mbad time\e[m";
			break;
		default:
			return "\e[3;31munknown\e[m";
	}
}

uc *
get_qtype(unsigned short qtype)
{
	switch(qtype)
	{
		case 1:
			return "A";
			break;
		case 2:
			return "NS";
			break;
		case 5:
			return "CNAME";
			break;
		case 6:
			return "SOA";
			break;
		case 12:
			return "PTR";
			break;
		case 13:
			return "HINFO (obsolete)";
			break;
		case 15:
			return "MX";
			break;
		case 16:
			return "TXT";
			break;
		case 17:
			return "RP (obsolete)";
			break;
		case 18:
			return "AFSDB";
			break;
		case 19:
			return "X25 (obsolete)";
			break;
		case 24:
			return "SIG (obsolete)";
			break;
		case 25:
			return "KEY (obsolete)";
			break;
		case 28:
			return "AAAA";
			break;
		case 29:
			return "LOC";
			break;
		case 33:
			return "SRV";
			break;
		case 35:
			return "NAPTR";
			break;
		case 36:
			return "KX";
			break;
		case 37:
			return "CERT";
			break;
		case 39:
			return "DNAME";
			break;
		case 41:
			return "OPT";
			break;
		case 42:
			return "APL";
			break;
		case 43:
			return "DS";
			break;
		case 44:
			return "SSHFP";
			break;
		case 45:
			return "IPSECKEY";
			break;
		case 46:
			return "RRSIG";
			break;
		case 47:
			return "NSEC";
			break;
		case 48:
			return "DNSKEY";
			break;
		case 49:
			return "DHCID";
			break;
		case 50:
			return "NSEC3";
			break;
		case 51:
			return "NSEC3PARAM";
			break;
		case 52:
			return "TLSA";
			break;
		case 55:
			return "HIP";
			break;
		case 59:
			return "CDS";
			break;
		case 60:
			return "CDNSKEY";
			break;
		case 61:
			return "OPENPGPKEY";
			break;
		case 99:
			return "SPF (obsolete)";
			break;
		case 249:
			return "TKEY";
			break;
		case 250:
			return "TSIG";
			break;
		case 251:
			return "IXFR";
			break;
		case 252:
			return "AXFR";
			break;
		case 255:
			return "ANY";
			break;
		case 256:
			return "URI";
			break;
		case 257:
			return "CAA";
			break;
		case 32768:
			return "TA";
			break;
		case 32769:
			return "DLV";
			break;
		default:
		return "unknown";
	}
}

void
DieSys(const char const *EMsg)
{
	fprintf(stderr, "\e[1;02m\e[3;31m%s - %s\e[m\n", EMsg, strerror(errno));
	exit(EXIT_FAILURE);
}

void
usage(int exit_status)
{
	fprintf(stderr, "usage: orion <hostname> [OPTIONS]\n"
			"  -D	send DHCP request to find local DNS server(s)\n"
			"  -S	specify DNS server [default is 127.0.1.1]\n"
			"  -t	specify the type of query:\n"
			"		A	IPv4 address\n"
			"		AAAA	IPv6 address\n"
			"		PTR	convert IPv4/IPv6 address to name\n"
			"		NAPTR	find SIP URI for telephone number\n"
			"		MX	mail exchange information\n"
			"		TXT	server text file information\n"
			"		SOA	zone authority information\n"
			"		NS	name server information\n"
			"		AXFR	request transfer of zone information\n"
			"  -x	accept resource records with stale time-to-live\n"
			"\n"
			"\n"
			"Examples:\n"
			"\n"
			"orion example.com -t AAAA -S 8.8.8.8\n"
			"	finds IPv6 address for \"example.com\"\n"
			"	using Google's DNS server at 8.8.8.8#53\n"
			"\n"
			"orion +447123456789 -t NAPTR\n"
			"	finds SIP URI for +447123456789\n"
			"	using default DNS resolver at 127.0.1.1#53\n"
			"\n"
			"orion example.com -t AAAA -D\n"
			"	finds IPv6 address for \"example.com\"\n"
			"	using DNS server found via DHCP request\n"
			"\n"
			"orion example.com -t NS -x\n"
			"	finds name server for \"example.com\" and\n"
			"	accepts records with stale time-to-live values\n");
	exit(exit_status);
}

uc *
get_opcode(unsigned short opcode)
{
	switch(opcode)
	{
		case 0:
			return("standard");
			break;
		case 1:
			return("inverse");
			break;
		case 2:
			return("status");
			break;
		case 4:
			return("notify");
			break;
		case 5:
			return("update");
			break;
		default:
			return("unknown");
	}
}

uc *
get_qclass(unsigned short qclass)
{
	switch(qclass)
	{
		case 1:
			return "internet";
			break;
		case DNS_QCLASS_CHAOS:
			return "chaos";
			break;
		case DNS_QCLASS_HESIOD:
			return "hesiod";
			break;
		case DNS_QCLASS_NONE:
			return "none";
			break;
		case DNS_QCLASS_ALL:
			return "all";
			break;
		default:
			return "unknown";
	}
}

int
print_info_dns(char *ptr, int flag, u16 tid, char *ns)
{
	assert(ptr);
	assert(ns);

	DNS_HEADER *d = NULL;
	DNS_QUESTION *q = NULL;
	char *p;
	int ok = 0;

	d = (DNS_HEADER *)ptr;
	p = (d + sizeof(DNS_HEADER));

	fprintf(stdout,
		"Questions %hu | Answers %hu | Authoritative %hu | Additional %hu\n",
		ntohs(d->qdcnt),
		ntohs(d->ancnt),
		ntohs(d->nscnt),
		ntohs(d->arcnt));

	fprintf(stdout, "  Query \"");

	if (!isdigit(*p) && !isalpha(*p))
		++p;

	while (*p != 0)
	{
		if (!isdigit(*p) && !isalpha(*p) && *p != 0x2d)
		{
			putchar('.');
			++p;
		}

		putchar(*p++);
	}

	fprintf(sdtout, "\" @SERVER %s:53\n", ns);
	++p;

	q = (DNS_QUESTION *)p;

	if (ntohs(d->ident) == tid)
		ok = 1;

	fprintf(stdout,
		"  Transaction ID 0x%hx %s\n",
		ntohs(d->ident),
		(flag?(ok?"\e[1;02m[\e[1;32mVALID\e[m\e[1;02m]\e[m":"\e[1;02m[\e[1;31mINVALID\e[m\e[1;02m]\e[m"):""));

	fprintf(stdout,
		"  FLAGS: %s %s %s %s %s %s %s  QTYPE: %s  QCLASS: %s  STATUS: %s\r\n",
		d->qr?"qr":"",
		d->aa?"aa":"",
		d->tc?"tc":"",
		d->rd?"rd":"",
		d->ra?"ra":"",
		d->ad?"ad":"",
		d->cd?"cd":"",
		get_qtype(ntohs(q->qtype)),
		get_qclass(ntohs(q->qclass)),
		get_rcode(d->rcode));

	putchar('\n');

	return 0;
}

int
encode_name(char *qname, char *host, size_t *len)
{
	int qidx = 0;
	char *p;
	char *q;
	size_t l = strlen((char *)host);
  
	p = q = host;
  
	while (1)
	{
		q = memchr((char *)p, '.', l);

		if (!q)
		{
			q = (host + len);
			qname[qidx++] = (uc)(q - p);
			memcpy((char *)(qname + qidx), p, (q - p));
			qidx += (q - p);
			break;
		}

		qname[qidx++] = (uc)(q - p);
		memcpy((char *)(qname + qidx), p, (q - p));
		qidx += (q - p);
		p = ++q;
	}

	*len = strlen(qname);
	return 0;
}

static inline off_t __label_off(uc *ptr)
{
	return ((*ptr * 0x100) + *(ptr + 1) - DNS_LABEL_OFFSET_BIAS);
}

int
decode_name(char *cur_pos, char *in, buf_t *out, size_t *delta)
{
	assert(rcvd);
	assert(buf);
	assert(target);
	assert(delta);

	int i;
	size_t len;
	size_t __delta = 0;
	off_t off;
	char *p;
	int jflag = 0;

/*
 * E.g., (B == octet of data)
 *
 * BBBB5orion2co2ukBBBBBBBBBBBBBBBBBBBB3www9astronomy[>=192][4]
 *
 * After www.astronomy, the offset to the desired label from
 * the start of the received data is encoded in the next two bytes
 * if the next immediate octet is >= 192.
 */

	buf_clear(out);

	for (p = cur_pos; *p != 0; ++p)
	{
		if ((unsigned char)*p >= 0xc0)
		{
			off = __label_off(p);
			p = (in + off);
			jflag = 1;
			off = 0;
		}

		buf_append_ex(out, p, 1);

		if (!jflag)
			++__delta;
	}

	if (jflag)
		p = (cur_pos + __delta + 1);

	++p;

/*
 * Replace the encoded label lengths with '.'
 */
	buf_collapse(out, (off_t)0, (size_t)1);
	for (i = 0; i < out->data_len; ++i)
	{
		if (!isascii(out->buf_head[i]))
			out->buf_head[i] = '.';
	}

	*delta = (p - cur_pos);

#if 0
	for (p = (uc *)rcvd; *p != 0; ++p)
	{
		if (*p >= 0xc0) // >= 192
		  {
			offset = ((*p) * 256) + *(p+1) - (192*256);
			p = (uc *)(buf + offset);
			jmp_fl = 1;
			offset = 0;
		  }
		target[len++] = *p;
		if (!jmp_fl)
			++delt;
	}
	if (jmp_fl == 1)
		{ p = (start + delt); ++p; }
	++p;
	*delta = (p - start);

	/* convert to normal format */
	for (i = 0; i < len; ++i)
	  {
		target[i] = target[i+1];
		if (!isalpha(target[i]) && !isdigit(target[i]) && target[i] != '-')
			target[i] = '.';
	  }
	i = 0;
#endif

	return 0;
}

int
convert_to_ptr(char *name, char *host, size_t *qnamelen)
{
	assert(name);
	assert(host);
	assert(qnamelen);

	int i;
	char *p;
	char *q;
	char *e;
	char *tmp;
	size_t host_len = strlen(host);
	size_t len;
	char _1[4], _2[4], _3[4], _4[4];

	asseert(host_len < hostmax);

	if (!(tmp = calloc_e(tmp, DEFAULT_TMP_BUF_SIZE, 1)))
		goto fail;

	e = (host + host_len);

	host[host_len++] = '.';
	p = host;

	q = memchr(p, '.', (e - p));
	memcpy((void *)_1, (void *)p, (q - p));
	_1[q - p] = 0;

	p = ++q;

	q = memchr(p, '.', (e - p));
	memcpy((void *)_2, (void *)p, (q - p));
	_2[q - p] = 0;

	p = ++q;

	q = memchr(p, '.', (e - p));
	memcpy((void *)_3, (void *)p, (q - p));
	_3[q - p] = 0;

	p = ++q;

	q = memchr(p, '.', (e - p));
	memcpy((void *)_4, (void *)p, (q - p));
	_4[q - p] = 0;

	sprintf(tmp, "%s.%s.%s.%s.in-addr.arpa", _4, _3, _2, _1);
	len = strlen(tmp);
	tmp[len++] = '.';
	tmp[len] = 0;

	if (encode_name(name, tmp, qnamelen) < 0)
		goto fail;

	free(tmp);
	tmp = NULL;

	return 0;

	fail:
	if (tmp)
	{
		free(tmp);
		tmp = NULL;
	}

	return -1;
}

int
convert_to_ptr6(char *out, char *in, size_t *out_len)
{
	assert(out);
	assert(in);
	assert(out_len);

	int k;
	char *p1;
	char *p2;
	char *t;
	char *e;
	buf_t tmp;
	size_t len;

	if (buf_init(&tmp, TMP_BUF_DEFAULT_SIZE) < 0)
		goto fail;

	len = strlen((char *)in);
	e = (in + len);
	k = 0;

	/*
	 * 2a03:2880:f12a:183:face:b00c:0:25de
	 *                ^             ^
	 *
	 * add in zeros where needed
	 */
	p1 = p2 = in;
	t = tmp;

	while (1)
	{
		k = 0;

		p1 = memchr(p1, ':', (e - p1));

		if (p1 == e && p2 == e)
			break;

		if ((p1 - p2) < 4)
		{
			while (k < (4 - (p1 - p2)))
			{
				buf_append(&tmp, "0");
				//*t++ = '0';
				++k;
			}

			while (p2 != p1)
			{
				buf_append_ex(&tmp, p2, 1);
				//*t++ = *p2++;
			}

			if (p1 != e)
			{
				buf_append_ex(&tmp, p1, 1);
				//*t++ = *p1++;
				++p2;
			}
		}
		else
		{
			while (p2 != p1)
			{
				buf_append_ex(&tmp, p2, 1);
				//*t++ = *p2++;
			}

			if (p1 != e)
			{
				buf_append_ex(&tmp, p1, 1);
				//*t++ = *p1++;
				++p2;
			}
		}
	}
	
	*t = 0;
	*out_len = strlen((char *)tmp);
	--t;

	p1 = out;
	while (t >= tmp)
	{
		if (*t == ':')
			--t;
		*p1++ = *t--;
		*p1++ = 0x01;
	}

	t = tmp;

	memcpy(p1, "ip6.arpa.", 9);

	p1 += 9;
	*p1 = 0;

	buf_destroy(&tmp);
	return 0;

	fail:
	buf_destroy(&tmp);

	return -1;
}

int
convert_nr_e164(char *target, char *number, size_t *target_len)
{
	assert(target);
	assert(number);
	assert(target_len);

	char *e = (number + strlen(number));
	char *t = NULL;
	buf_t tmp;

	if (buf_init(&tmp, TMP_BUF_DEFAULT_SIZE) < 0)
		goto fail;

	numlen = strlen(number);
	t = tmp;

	while (e >= number)
	{
		buf_append(&tmp, e, 1);
		buf_append(&tmp, ".");
		--e;
	}

	buf_append(&tmp, "e164.arpa");

	memcpy(target, tmp.buf_head, tmp.data_len);
	*target_len = tmp.data_len;

	buf_destroy(&tmp);
	return 0;

	fail:

	buf_destroy(&tmp);
	return -1;
}

int
handle_nptr_record(DNS_RRECORD *record)
{
	assert(record);

	char *p;
	char *name;
	size_t len, delta;
	int hostmax;
	NAPTR_DATA *naptr = NULL;

	naptr = (NAPTR_DATA *)record->rdata;

	len = ntohs(record->resource->len);
	fprintf(stdout, "\e[3;02mNAPTR record\e[m\n\n");
	p = record->name;
	fprintf(stdout, "\e[3;02mnumber\e[m ");
	fprintf(stdout, "%.*s\n", (int)len, p);

	fprintf(stdout, "\e[3;02morder\e[m %hu\n", ntohs(naptr->order));
	fprintf(stdout, "\e[3;02mpreference\e[m %hu\n", ntohs(naptr->pref));
	fprintf(stdout, "\e[3;02mservices\e[m %s\n", naptr->services);
	fprintf(stdout, "%s\n", naptr->services);
	fprintf(stdout, "\e[3;02mregex\e[m %s\n", naptr->regex);
	p = naptr->replace;

	if (!(name = calloc_e(name, hostmax, sizeof(uc))))
		goto fail;

	delta = 0;
	if (get_name(p, record->rdata, name, &delta) < 0)
		goto fail;

	p += delta;
	fprintf(stdout, "\e[3;02mreplacement\e[m %s\n", name);

	free(name);
	name = NULL;

	return 0;

	fail:

	if (name)
	{
		free(name);
		name = NULL;
	}

	return -1;
}

static sigjmp_buf __timeout;

static void
handle_timeout(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__timeout, 1);
}

int
do_udp(uc *buf, size_t size, uc *ns)
{
	assert(buf);
	assert(ns);

	struct sockaddr_in sin;
	struct sigaction oact;
	struct sigaction nact;
	ssize_t ret = 0;
	int s;
	time_t now;
	struct tm *_time;
	static char tstring[50];

	clear_struct(&oact);
	clear_struct(&nact);

	nact.sa_handler = handle_timeout;
	nact.sa_flags = 0;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGINT);
	sigaddset(&nact.sa_mask, SIGQUIT);

	if (sigaction(SIGALRM, &nact, &oact) < 0)
	{
		fprintf(stderr, "do_udp: failed to set signal handler for SIGALRM (%s)\n", strerror(errno));
		goto fail;
	}

	clear_struct(&sin);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(DNS_PORT_NR);

	if (inet_pton(AF_INET, (char *)ns, &sin.sin_addr.s_addr) < 0)
	{
		fprintf(stderr, "do_udp: inet_pton error (%s)\n", strerror(errno));
		goto fail;
	}

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
		fprintf(stderr, "do_udp: failed to open UDP socket (%s)\n", strerror(errno));
		goto fail;
	}

	now = time(NULL);
	if (!(_time = localtime(&now)))
	{
		fprintf(stderr, "do_udp: failed to get local time (%s)\n", strerror(errno));
		goto fail;
	}

	if (strftime(tstring, 30, "%a %d %b %Y %H:%M:%S", _time) < 0)
	{
		fprintf(stderr, "do_udp: failed to convert time to string format (%s)\n", strerror(errno));
		goto fail;
	}

	fprintf(stdout, "\n\e[3;02mDNS Query (sent %s [TZ %s])\e[m\n", tstring, _time->tm_zone);

	if (print_info_dns(buf, 0, getpid(), ns) == -1)
		goto fail;

	if (sendto_a(s, buf, size, 0, (struct sockaddr *)&s4, (socklen_t)sizeof(s4)) == -1)
	{
		fprintf(stderr, "do_udp: failed to send DNS request to server (%s)\n", strerror(errno));
		goto fail;
	}

	if (sigsetjmp(__timeout, 1) != 0)
	{
		fprintf(stderr, "do_udp: timed out waiting for response\n");
		goto fail;
	}

	alarm(DNS_MAX_TIME_WAIT);

	if ((ret = recv(s, buf, DNS_MAX_UDP_SIZE, 0)) < 0)
	{
		alarm(0);
		fprintf(stderr, "do_udp: recv error (%s)\n", strerror(errno));
		goto fail;
	}

	alarm(0);

	buf[ret] = 0;

	sigaction(SIGALRM, &oact, NULL);
	return ret;

	fail:
	sigaction(SIGALRM, &oact, NULL);
	return -1;
}

static sigjmp_buf __timeout_tcp;

static void
handle_timeout_tcp(int signo)
{
	if (signo != SIGALRM)
		return;

	siglongjmp(__timeout_tcp, 1);
}

int
do_tcp(uc *buf, size_t size, uc *ns)
{
	assert(buf);
	assert(ns);

	struct sockaddr_in sin;
	struct sigaction oact;
	struct sigaction nact;
	ssize_t ret = 0;
	int s;
	time_t now;
	struct tm *_time;
	static char tstring[50];

	clear_struct(&oact);
	clear_struct(&nact);

	nact.sa_handler = handle_timeout_tcp;
	nact.sa_flags = 0;
	sigemptyset(&nact.sa_mask);
	sigaddset(&nact.sa_mask, SIGINT);
	sigaddset(&nact.sa_mask, SIGQUIT);

	if (sigaction(SIGALRM, &nact, &oact) < 0)
	{
		fprintf(stderr, "do_tcp: failed to set signal handler for SIGALRM (%s)\n", strerror(errno));
		goto fail;
	}

	clear_struct(&sin);

	sin.sin_family = AF_INET;
	sin.sin_port = htons(DNS_PORT_NR);

	if (inet_pton(AF_INET, ns, &sin.sin_addr.s_addr) < 0)
	{
		fprintf(stderr, "do_tcp: inet_pton error (%s)\n", strerror(errno));
		goto fail;
	}

	if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		fprintf(stderr, "do_tcp: failed to open TCP socket (%s)\n", strerror(errno));
		goto fail;
	}

	if (sigsetjmp(__timeout_tcp, 0) != 0)
	{
		fprintf(stderr, "do_tcp: timed out waiting for response\n");
		goto fail;
	}

	alarm(DNS_MAX_TIME_WAIT);

	if (connect(s, (struct sockaddr *)&sin, (socklen_t)sizeof(sin)) != 0)
	{
		alarm(0);
		fprintf(stderr, "do_tcp: failed to connect to DNS server (%s)\n", strerror(errno));
		goto fail;
	}

	alarm(0);

	now = time(NULL);

	if ((_time = localtime(&seed)) == NULL)
	{
		fprintf(stderr, "do_tcp: failed to get local time (%s)\n", strerror(errno));
		goto fail;
	}

	if (strftime(tstring, 30, "%a %d %b %Y %H:%M:%S", _time) < 0)
	{
		fprintf(stderr, "do_tcp: failed to convert local time to string format (%s)\n", strerror(errno));
		goto fail;
	}

	fprintf(stdout, "\n\e[3;02mDNS Query (sent %s [TZ %s])\e[m\n", tstring, _time->tm_zone);

	if (print_info_dns(buf, 0, getpid(), ns) == -1)
		goto fail;

	if ((ret = send_a(s, buf, size, 0)) == -1)
	{
		fprintf(stderr, "do_tcp: send_a error (%s)\n", strerror(errno));
		goto fail;
	}

	alarm(DNS_MAX_TIME_WAIT);

	if ((ret = recv_a(s, buf, BUFSIZ, 0)) == -1)
	{
		alarm(0);
		fprintf(stderr, "do_tcp: recv_a error (%s)\n", strerror(errno));
		goto fail;
	}

	alarm(0);

	shutdown(s, SHUT_RDWR);
	close(s);
	s = -1;

	buf[ret] = 0;

	return ret;

	fail:

	return -1;
}

int
get_records(cache_t *cachep, u16 cnt, char *ptr, char *buf, size_t size, size_t *delta)
{
	int i;
	char *p;

	*delta = 0;
	p = ptr;

	for (i = 0; i < cnt; ++i)
	{
		if (!(rrecord_ptr = (DNS_RRECORD *)cache_alloc(cachep, &rrecord_ptr)))
		{
			fprintf(stderr, "get_records: failed to allocate resource record cache object\n");
			goto fail;
		}

		if (get_name(p, buf, rrecord_ptr->name, delta) < 0)
			goto fail;

		p += *delta;

		memcpy(rrecord_ptr->resource, p, sizeof(DNS_RDATA));

		p += sizeof(DNS_RDATA);

		memcpy(rrecord_ptr->rdata, p, ntohs(rrecord_ptr->resource->len));

		p += ntohs(rrecord_ptr->resource->len);
	}

	*delta = (p - ptr);
	return 0;

	fail:
	return -1;
}

int
print_answers(cache_t *cachep, u16 cnt, char *buf, int qtype)
{
	int i;
	buf_t tmp;
	buf_t domain;
	buf_t mx;
	struct in_addr *inet;
	struct in6_addr *inet6;
	static char inet6_str[INET6_ADDRSTRLEN];
	char *inet_str;
	u16 *a16;
	u16 pref;
	u16 type;
	u32 serial;
	u32 refresh;
	u32 retry;
	u32 expire;
	u32 min;
	u32 *a32;
	char *p;
	size_t delta;

	if (buf_init(&tmp, hostmax) < 0)
		goto fail;
	if (buf_init(&domain, hostmax) < 0)
		goto fail_release_bufs;
	if (buf_init(&mx, hostmax) < 0)
		goto fail_release_bufs;

	DNS_RRECORD *r = (DNS_RRECORD *)cachep->cache;

	for (i = 0; i < cnt; ++i)
	{
		if (!TTL_OK(ntohl(r->resource->ttl)))
		{
			if (!STALE_OK)
			{
				fprintf(stdout, "%sResource record is stale (ttl: %u)%s\n",
					ntohl(r->resource->ttl));

				continue;
			}
		}

		type = ntohs(r->resource->type);
		switch(type)
		{
			case 1: /* IP address */
				if (3 == r->resource->_class)
				{
					p = r->rdata;
					if (get_name(p, buf, &tmp, &delta) < 0)
						goto fail;

					p += delta;

					a16 = (u16 *)p;
					fprintf(stdout,
						"%s%18s%s %s [%u]\n"
						"%18s %0o\n",
						"Chaos Name",
						tmp.buf_head,
						ntohl(r->resource->ttl),
						"Chaos Address",
						*a16);

					p += sizeof(u16);
				}
				else
				{
					p = r->rdata;
					inet = (struct in_addr *)p;
					fprintf(stdout,
						"%s%18s%s %s [%u]\n",
						"IPv4 Address",
						inet_ntoa(*inet),
						ntohs(r->resource->ttl));
				}
				break;
			case 2:
				p = r->rdata;

				if (get_name(p, buf, &tmp, &delta) < 0)
					goto fail;

				p += delta;

				fprintf(stdout,
						"%s%18s%s %s [%u]\n",
						"Name Server",
						tmp.buf_head,
						ntohs(r->resource->ttl));

				break;
			case 5:
				p = r->rdata;

				if (get_name(p, buf, &tmp, &delta) < 0)
					goto fail;

				p += delta;

				fprintf(stdout,
						"%s%18s%s %s [%u]\n",
						"Canonical Name",
						tmp.buf_head,
						ntohl(r->resource->ttl));

				break;
			case 6:
				p = r->rdata;

				if (get_name(p, buf, &domain, &delta) < 0)
					goto fail;

				p += delta;

				if (get_name(p, buf, &mx, &delta) < 0)
					goto fail;

				serial = ntohl(*((u32 *)p));
				p += sizeof(u32);

				refresh = ntohl(*((u32 *)p));
				p += sizeof(u32);

				retry = ntohl(*((u32 *)p));
				p += sizeof(u32);

				expire = ntohl(*((u32 *)p));
				p += sizeof(u32);

				min = ntohl(*((u32 *)p));
				p += sizeof(u32);

				fprintf(stdout,
						"%s%18s%s %s\n"
						"%s%18s%s %s\n"
						"%s%18s%s %u\n"
						"%s%18s%s %d\n"
						"%s%18s%s %d\n"
						"%s%18s%s %d\n"
						"%s%18s%s %d\n"
						"%s%18s%s %u\n",
						COL_GREEN, "domain", COL_END, domain.buf_head,
						COL_GREEN, "mail", COL_END, mx.buf_head,
						COL_GREEN, "S#", COL_END, serial,
						COL_GREEN, "REFR", COL_END, refresh,
						COL_GREEN, "RETR", COL_END, retry,
						COL_GREEN, "EXP", COL_END, expire,
						COL_GREEN, "MIN", COL_END, min,
						COL_GREEN, "TTL", COL_END, ntohl(r->resource->ttl));

				break;
			case 12:
				p = r->rdata;

				if (get_name(p, buf, &tmp, &delta) < 0)
					goto fail;

				p += delta;

				fprintf(stdout,
						"%s%18s%s %s [%u]\n",
						COL_GREEN, "Pointer", COL_END, tmp.buf_head, ntohl(r->resource->ttl));

				break;
			case 15: /* Mail Exchange Record */
				p = r->rdata;

				pref = ntohs(*((u16 *)p));
				p += sizeof(u16);

				if (get_name(p, buf, &mx, &delta) < 0)
					goto fail;

				p += delta;

				fprintf(stdout,
						"%s%18s%s %s (pref: %hu) [%u]\n",
						COL_GREEN, "Mail Exchange", COL_END, mx.buf_head, pref, ntohl(r->resource->ttl));

				break;
			case 16: /* Text Record */
				p = r->rdata;
				fprintf(stdout, "%s%18s%s\n", COL_GREEN, "Txt Record", COL_END);
				while (p < (r->rdata + ntohs(r->resource->len)))
				{
					while (iscntrl(*p) && *p != 0x0d && *p != 0x0a)
						++p;

					putchar(*p++);
				}
				putchar('\n');

				break;
			case 28: /* AAAA record (ipv6) */
				p = r->rdata;
				a128 = (struct in6_addr *)p;
				if (!inet_ntop(AF_INET6, &a128->s6_addr, a128_str, INET6_ADDRSTRLEN))
				{
					fprintf(stderr, "print_records: inet_ntop error (%s)\n", strerror(errno));
					goto fail;
				}

				p += ntohs(r->resource->len);

/* colour used \e[3;02m */
				fprintf(stdout, "%s%18s%s %s [%u]\n",
						COL_GREEN, "IPv6 Address", COL_END,
						a128_str,
						ntohl(r->resource->ttl));
				break;
			case 35: /* NAPTR record */
			if (HandleNAPTRrecord(&ans_array[k]) == -1)
				{ perror("GetAnswers: HandleNAPTRrecord"); goto __err; }
			break;
			case(252): /* AXFR record */
			/*TODO*/
			break;
			case(256): /* URI record */
			p = ans_array[k].rdata;
			if (GetName(p, buf, string, &delta) == -1)
				goto __err;
			p += delta;
			printf("\e[3;02m%18s\e[m %s [%u]\n", 
				"URI",
				string,
				ntohl(ans_array[k].resource->ttl));
			break;
			default:
			if (ans_array[k].name != NULL) free(ans_array[k].name);
			if (ans_array[k].rdata != NULL) free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			goto __err;
		  }
	  }

	buf_destroy(&tmp);
	buf_destroy(&domain);
	buf_destroy(&mx);
	
	cache_clear_all(cachep);
	return 0;

	fail_release_bufs:
	buf_destroy(&tmp);
	buf_destroy(&domain);
	buf_destroy(&mx);

	fail:

	return -1;
}

static int
qtype_atov(char *s)
{
	if (!strcasecmp("a", s))
		return DNS_QTYPE_A;
	else
	if (!strcasecmp("mx", s))
		return DNS_QTYPE_MX;
	else
	if (!strcasecmp("nptr", s))
		return DNS_QTYPE_NPTR;
	else
	if (!strcasecmp("aaaa", s))
		return DNS_QTYPE_AAAA;
	else
	if (!strcasecmp("ixfr", s))
		return DNS_QTYPE_IXFR;
	else
	if (!strcasecmp("axfr", s))
		return DNS_QTYPE_AXFR;
	else
		return DNS_QTYPE_A;
}

static char *
__dns_qname(char *buf)
{
	return (buf + sizeof(DNS_HEADER));
}

int
do_query(char *host, char *ns, int qtype, int qclass)
{
	char *buf;
	char *qname;
	char *p;
	char *e164;
	u16 tid;
	DNS_RRECORD *answers;
	DNS_RRECORD *auth;
	DNS_RRECORD *additional;
	DNS_HEADER *dns;
	DNS_QUESTION *question;
	struct timespec time1;
	struct timespec time2;
	size_t qname_len;
	size_t tosend;
	size_t total;
	size_t delta;
	double diff;
	int tcp = 0;

	if (!(buf = calloc_e(buf, BUFSIZ, 1)))
		goto fail;

	memset(buf, 0, BUFSIZ);
	tid = htons(getpid());
	qname = __dns_qname(buf);

	dns = (DNS_HEADER *)buf;
	dns->ident = tid;
	dns->rd = 1;
	dns->cd = 1;
	dns->qdcnt = htons(1);

	if (DNS_QTYPE_PTR == qtype)
	{
		if (convert_to_ptr(qname, host, &qnamelen) < 0)
			goto fail;
	}
	else
	if (DNS_QTYPE_NAPTR == qtype)
	{
		if (!(e164 = calloc_e(e164, hostmax*2, 1)))
			goto fail;

		if (convert_nr_e164(e164, host, &qnamelen) < 0)
			goto fail;

		if (encode_name(qname, e164, &qnamelen) < 0)
			goto fail;
	}
	else
	{
		if (encode_name(qname, host, &qnamelen) < 0)
			goto fail;
	}

	p = (DNS_QUESTION *)&buf[sizeof(DNS_HEADER)+qnamelen+1];
	p->qtype = htons(qtype);
	p->qclass = htons(qclass);

	tosend = sizeof(DNS_HEADER) + qnamelen + 1 + sizeof(DNS_QUESTION);
	total = 0;

	clear_struct(&time1);
	clear_struct(&time2);

	if (clock_gettime(CLOCK_REALTIME, &time1) < 0)
	{
		fprintf(stderr, "do_query: clock_gettime (CLOCK_REALTIME) error (%s)\n", strerror(errno));
		goto fail;
	}

	if (DNS_QTYPE_AXFR == qtype)
	{
		if ((total = do_tcp(buf, tosend, ns)) < 0)
			goto fail;

		tcp = 1;
	}
	else
	{
		if ((total = do_udp(buf, tosend, ns)) < 0)
			goto fail;
	}

	if (clock_gettime(CLOCK_REALTIME, &time2) < 0)
	{
		fprintf(stderr, "do_query: clock_gettime (CLOCK_REALTIME) error (%s)\n", strerror(errno));
		goto fail;
	}

	diff = ((double)(((double)t2.tv_nsec/NSEC_PER_SEC) - ((double)t1.tv_nsec/NSEC_PER_SEC)));

	fprintf(stderr, "\e[3;02mDNS Response (%3.2lf ms; Protocol %s)\e[m\r\n",
			diff,
			(tcp?"TCP":"UDP"));

	dns = (DNS_HEADER *)buf;
	p = buf;

	if (print_info_dns(p, 1, tid, ns) < 0)
		goto fail;

	p = &buf[sizeof(DNS_HEADER) + qnamelen + 1 + sizeof(DNS_QUESTION)];

	if (ntohs(dns->ancnt) > 0)
	{
		if (get_records(answer_cache, ntohs(dns->ancnt), p, buf, total, &delta) < 0)
			goto fail;

		fprintf(stderr, "\e[1;02m\e[3;32m\tANSWER RESOURCE RECORDS\e[m\r\n");
		if (print_answers(answer_cache, ntohs(dns->ancnt), buf, qtype) < 0)
			goto fail;

		p += delta;
	}

	if (ntohs(dns->nscnt) > 0)
	{
		if (get_records(auth_cache, ntohs(dns->nscnt), p, buf, total, &delta) < 0)
			goto fail;

		fprintf(stdout, "\e[1;02m\e[3;32m\tAUTHORITATIVE RESOURCE RECORDS\e[m\r\n");
		if (print_answers(auth_cache, ntohs(dns->nscnt), buf, qtype) < 0)
			goto fail;

		p += delta;
	}

	if (ntohs(dns->arcnt) > 0)
	{
		if (get_records(additional_cache, ntohs(dns->arcnt), p, buf, total, &delta) < 0)
			goto fail;

		fprintf(stdout, "\e[1;02m\e[3;32m\tADDITIONAL RESOURCE RECORDS\e[m\r\n");
		if (print_answers(additional_cache, ntohs(dns->arcnt), buf, qtype) < 0)
			goto fail;

		p += delta;
	}

	free(buf);
	buf = NULL;

	return 0;

	fail:

	if (buf)
	{
		free(buf);
		buf = NULL;
	}
	return -1;
}

int
main(int argc, char *argv[])
{
	char c;
	static char qtype_str[DNS_MAX_QTYPE_STRLEN];
	static char qclass_str[DNS_MAX_QCLASS_STRLEN];
	char ns[INET_ADDRSTRLEN];
	uc *telno = NULL;
	uc *p = NULL;
	uc *host = NULL;
	int DNS_SRV_FL = 0;
	int k;
	size_t len;
	int qtype = 0;
	int qclass = 0;

	if (argc == 1)
		usage(EXIT_FAILURE);

	host = argv[1];

	if (strlen(host) >= hostmax)
	{
		fprintf(stderr, "\e[3;31mmain: hostname exceeds maximum number of chars allowed\e[m\n");
		errno = ENAMETOOLONG;
		goto fail;
	}

	while ((c = getopt(argc, argv, "hS:t:c:x")) != -1)
	{
		switch(c)
		{
			case 0x78:
				STALE_OK = 1;
				break;
			case 0x68:
				usage(EXIT_SUCCESS);
				break;
			case 0x53:
				if (strncpy(ns, optarg, INET_ADDRSTRLEN) == NULL)
				{
					perror("strncpy");
					goto fail;
				}
				DNS_SRV_FL = 1;
				break;
			case 0x63: /* specify class */
				len = strlen(optarg);
				if (strncpy(classStr, optarg, len) == NULL)
				{
					perror("strncpy");
					goto fail;
				}
				classStr[len] = 0;
				for (k = 0; (size_t)k < len; ++k)
					classStr[k] = tolower(classStr[k]);

				if (strncmp(classStr, "in", 2) == 0)
					qclass = 1;
				else
				if (strncmp(classStr, "chaos", 5) == 0)
					qclass = 3;
				else
					qclass = 1;
				break;
			case 0x74:
				len = strlen(optarg);
				assert(len < DNS_MAX_QTYPE_STRLEN);
				memcpy((void *)qtype_str, (void *)optarg, len);
				qtype_str[len] = 0;
				qtype = qtype_atov(qtype_str);

				if (strncmp(typeStr, "a", 1) == 0 &&
			  	  strncmp(typeStr, "aaaa", 4) != 0 &&
			  	  strncmp(typeStr, "axfr", 4) != 0)
			  {
					qtype = 1;
					goto __got_type;
			  }
				else
				if (strncmp(typeStr, "ns", 2) == 0)
				{
					qtype = 2;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "cname", 5) == 0)
				{
					qtype = 5;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "soa", 3) == 0)
				{
					qtype = 6;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "ptr", 3) == 0)
				{
					qtype = 12;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "mx", 2) == 0)
				{
					qtype = 15;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "txt", 3) == 0)
				{
					qtype = 16;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "aaaa", 4) == 0)
				{
					qtype = 28;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "naptr", 5) == 0)
				{
					qtype = 35;
					p = host;
					len = strlen(argv[1]);

					for (k = 0; (size_t)k < len; ++k)
					{
						if (isalpha(argv[1][k]))
						{
							errno = EPROTO;
							perror("invalid argument for NAPTR");
							goto fail;
						}
					}

					if (!(telno = (uc *)calloc_e(telno, hostmax, sizeof(char))))
						goto fail;

					char *e = (host + strlen(host));
					k = 0;
					while (p < e)
					{
						if (*p == 0x2d || *p == 0x2b || *p == 0x20)
							++p;
						else
							telno[k++] = *p++;
					}
					telno[k] = 0;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "axfr", 4) == 0)
				{
					qtype = 252;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "any", 3) == 0)
				{
					qtype = 255;
					goto __got_type;
				}
				else
				{
					qtype = 255;
					goto __got_type;
				}
				__got_type:
				break;
			case 0x3f:
				usage(EXIT_FAILURE);
				break;
			default:
				usage(EXIT_FAILURE);
		}
	}

	if (!DNS_SRV_FL)
	{
		strncpy(ns, "127.0.1.1", INET_ADDRSTRLEN);
		ns[strlen("127.0.1.1")] = 0;
	}

	if (qclass == 0)
		qclass = 1;

	if (telno == NULL)
	{
		if (DoQuery(host, ns, qtype, qclass) == -1)
			goto fail;
	}
	else
	{
		if (DoQuery(telno, ns, qtype, qclass) == -1)
			goto fail;
	}

	if (telno)
		free(telno);

	exit(EXIT_SUCCESS);

	fail:
	if (telno)
		free(telno);

	exit(EXIT_FAILURE);
}
