#include "orion.h"

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
