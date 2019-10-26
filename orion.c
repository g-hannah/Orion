#include "orion.h"

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
		case QCLASS_CHAOS:
			return "chaos";
			break;
		case QCLASS_HESIOD:
			return "hesiod";
			break;
		case QCLASS_NONE:
			return "none";
			break;
		case QCLASS_ALL:
			return "all";
			break;
		default:
			return "unknown";
	}
}

int
convert_to_ptr6(uc *out, *uc in, size_t *out_len)
{
	assert(out);
	assert(in);
	assert(out_len);

	uc *tmp = NULL;
	uc *p1 = NULL;
	uc *p2 = NULL;
	uc *t = NULL;
	uc *e;
	int k;
	size_t len;

	if (!(tmp = (uc *)calloc_e(tmp, TMP_BUF_DEFAULT_SIZE, sizeof(uc))))
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
				*t++ = '0';
				++k;
			}

			while (p2 != p1)
				*t++ = *p2++;

			if (p1 != e)
			{
				*t++ = *p1++;
				++p2;
			}
		}
		else
		{
			while (p2 != p1)
				*t++ = *p2++;

			if (p1 != e)
			{
				*t++ = *p1++;
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
convert_nr_e164(uc *target, *uc number, size_t *target_len)
{
	assert(target);
	assert(number);
	assert(target_len);

	uc *tmp = NULL;
	uc *e = (number + strlen(number));
	uc *t = NULL;
	size_t len;

	if (!(tmp = (uc *)calloc_e(tmp, TMP_BUF_DEFAULT_SIZE, 1)))
		goto fail;

	numlen = strlen(number);
	t = tmp;

	while (e >= number)
	{
		*t++ = *e--;
		*t++ = '.';
	}

	sprintf(t, "%s", "e164.arpa");

	len = strlen(tmp);
	memcpy(target, tmp, len);
	*target_len = len;

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

	if ((ret = recv(s, buf, 512, 0)) < 0)
	{
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

int
convert_name(uc *qname, uc *host, size_t *len)
{
	int qidx = 0;
	uc *p = NULL;
	uc *q = NULL;
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

#define OFFSET_BIAS (0xc0 * 0x100)

static inline off_t __label_off(uc *ptr)
{
	return ((*ptr * 0x100) + *(ptr + 1) - OFFSET_BIAS);
}

int
decode_name(uc *rcvd, uc *buf, uc *target, size_t *delta)
{
	assert(rcvd);
	assert(buf);
	assert(target);
	assert(delta);

	int i;
	size_t len;
	size_t __delta = 0;
	off_t off;
	uc *start = NULL;
	uc *p = NULL;
	int jflag = 0;

/* blah3com0blahblahblahblahblahblahblah3www6google[192][4] */

	start = (uc *)rcvd;
	offset = 0;

	for (p = (uc *)rcvd; *p != 0; ++p)
	{
		if (*p >= 0xc0)
		{
			off = __label_off(p);
			p = (uc *)(buf + off);
			jflag = 1;
			off = 0;
		}

		target[len++] = *p;

		if (!jflag)
			++__delta;
	}

	if (jflag)
	{
		p = (start + __delta);
		++p;
	}

	for (i = 0; i < (len - 1); ++i)
	{
		target[i] = target[i+1];

		if (!isascii(target[i]))
			target[i] = '.';
	}

	target[--len] = 0;
	*delta = (p - start);

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
main(int argc, char *argv[])
{
	char c;
	char typeStr[20];
	char classStr[20];
	char ns[INET_ADDRSTRLEN];
	uc *telno = NULL;
	uc *p = NULL;
	uc *host = NULL;
	int DNS_SRV_FL = 0;
	int hostmax = 0;
	int k;
	size_t len;
	int q_type = 0;
	int q_class = 0;
//	atomic_t q_type = 0;
//	atomic_t q_class = 0;

	if (argc == 1)
		Usage();

	host = argv[1];

	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;

	if (strlen(host) >= hostmax)
	{
		fprintf(stderr, "\e[3;31mmain: hostname exceeds maximum number of chars allowed\e[m\r\n");
		errno = ENAMETOOLONG;
		goto fail;
	}

	while ((c = getopt(argc, argv, "hDS:t:c:x")) != -1)
	{
		switch(c)
		{
			case(0x78):
				STALE_OK = 1;
				break;
			case(0x68):
				Usage();
				break;
			case(0x44):
				if (DHCP_GetNS(ns) == -1)
				{
					perror("DHCP_GetNS");
					goto fail;
				}
				DNS_SRV_FL = 1;
				break;
			case(0x53):
				if (strncpy(ns, optarg, INET_ADDRSTRLEN) == NULL)
				{
					perror("strncpy");
					goto fail;
				}
				DNS_SRV_FL = 1;
				break;
			case(0x63): /* specify class */
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
					q_class = 1;
				else
				if (strncmp(classStr, "chaos", 5) == 0)
					q_class = 3;
				else
					q_class = 1;
				break;
			case(0x74):
				len = strlen(optarg);
				strncpy(typeStr, optarg, len);
				typeStr[len] = 0;
				for (int k = 0; k < (strlen(typeStr)); ++k)
					typeStr[k] = tolower(typeStr[k]);
				if (strncmp(typeStr, "a", 1) == 0 &&
			  	  strncmp(typeStr, "aaaa", 4) != 0 &&
			  	  strncmp(typeStr, "axfr", 4) != 0)
			  {
					q_type = 1;
					goto __got_type;
			  }
				else
				if (strncmp(typeStr, "ns", 2) == 0)
				{
					q_type = 2;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "cname", 5) == 0)
				{
					q_type = 5;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "soa", 3) == 0)
				{
					q_type = 6;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "ptr", 3) == 0)
				{
					q_type = 12;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "mx", 2) == 0)
				{
					q_type = 15;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "txt", 3) == 0)
				{
					q_type = 16;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "aaaa", 4) == 0)
				{
					q_type = 28;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "naptr", 5) == 0)
				{
					q_type = 35;
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
					q_type = 252;
					goto __got_type;
				}
				else
				if (strncmp(typeStr, "any", 3) == 0)
				{
					q_type = 255;
					goto __got_type;
				}
				else
				{
					q_type = 255;
					goto __got_type;
				}
				__got_type:
				break;
			case(0x3f):
				Usage();
				break;
			default:
				Usage();
		}
	}

	if (!DNS_SRV_FL)
	{
		strncpy(ns, "127.0.1.1", INET_ADDRSTRLEN);
		ns[strlen("127.0.1.1")] = 0;
	}

	if (q_class == 0)
		q_class = 1;

	if (telno == NULL)
	{
		if (DoQuery(host, ns, q_type, q_class) == -1)
			goto fail;
	}
	else
	{
		if (DoQuery(telno, ns, q_type, q_class) == -1)
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
