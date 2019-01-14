#include "dns.h"

int
main(int argc, char *argv[])
{
	static char c, typeStr[20], classStr[20], ns[INET_ADDRSTRLEN];
	static uc *telno = NULL, *p = NULL, *host = NULL;
	static int DNS_SRV_FL = 0;
	static int hostmax = 0, k;
	static _atomic_ q_type = 0, q_class = 0;

	if (argc == 1)
		Usage();
	host = argv[1];

	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	if (strlen(host) >= hostmax)
	  {
		fprintf(stderr, "\e[3;31mmain: hostname exceeds maximum number of chars allowed\e[m\r\n");
		errno = ENAMETOOLONG;
		goto __err;
	  }
	while ((c = getopt(argc, argv, "hS:t:c:x")) != -1)
	  {
		switch(c)
		  {
			case(0x78):
			STALE_OK = 1;
			break;
			case(0x68):
			Usage();
			break;
			case(0x53):
			if (strncpy(ns, optarg, INET_ADDRSTRLEN) == NULL)
				{ perror("strncpy"); goto __err; }
			DNS_SRV_FL = 1;
			break;
			case(0x63): /* specify class */
			if (strncpy(classStr, optarg, strlen(optarg)) == NULL)
				{ perror("strncpy"); goto __err; }
			for (int k = 0; k < strlen(optarg); ++k)
				classStr[k] = tolower(classStr[k]);
			if (strncmp(classStr, "in", 2) == 0)
				q_class = 1;
			else if (strncmp(classStr, "chaos", 5) == 0)
				q_class = 3;
			else
				q_class = 1;
			break;
			case(0x74):
			strncpy(typeStr, optarg, strlen(optarg));
			for (int k = 0; k < (strlen(typeStr)); ++k)
				typeStr[k] = tolower(typeStr[k]);
			if (strncmp(typeStr, "a", 1) == 0 &&
			    strncmp(typeStr, "aaaa", 4) != 0 &&
			    strncmp(typeStr, "axfr", 4) != 0)
			  {
				q_type = 1;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "ns", 2) == 0)
			  {
				q_type = 2;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "cname", 5) == 0)
			  {
				q_type = 5;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "soa", 3) == 0)
			  {
				q_type = 6;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "ptr", 3) == 0)
			  {
				q_type = 12;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "mx", 2) == 0)
			  {
				q_type = 15;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "txt", 3) == 0)
			  {
				q_type = 16;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "aaaa", 4) == 0)
			  {
				q_type = 28;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "naptr", 5) == 0)
			  {
				q_type = 35;
				p = host; k = 0;
				for (k = 0; k < strlen(argv[1]); ++k)
					if (isalpha(argv[1][k]))
						{ errno = EPROTO; perror("invalid argument for NAPTR"); goto __err; }
				k = 0;
				if (!(telno = (uc *)calloc_e(telno, hostmax, sizeof(char))))
					goto __err;
				while (p < (host + strlen(host)))
				  {
					if (*p == 0x2d || *p == 0x2b || *p == 0x20)
						++p;
					else
						telno[k++] = *p++;
				  }
				telno[k] = 0;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "axfr", 4) == 0)
			  {
				q_type = 252;
				goto __got_type;
			  }
			else if (strncmp(typeStr, "any", 3) == 0)
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
			goto __err;
	  }
	else
	  {
		if (DoQuery(telno, ns, q_type, q_class) == -1)
			goto __err;
	  }

	if (telno != NULL) free(telno);
	exit(0);

	__err:
	if (telno != NULL) free(telno);
	exit(-1);
}
