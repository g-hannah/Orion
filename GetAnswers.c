#include "dns.h"

ssize_t
GetAnswers(DNS_RRECORD ans_array[], u16 acnt, uc *buf, _atomic_ q_type)
{
	if (ans_array == NULL || acnt <= 0 || buf == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }

	static int k, hostmax = 0, err;
	static uc *string = NULL, *domain = NULL, *mailn = NULL;
	static char a128_str[INET6_ADDRSTRLEN], *a32_str = NULL;
	static struct in_addr *a32 = NULL;
	static struct in6_addr *a128 = NULL;
	static u16 *pref = NULL, *a16 = NULL;
	static u32 *serial = NULL, *refresh = NULL, *retry = NULL, *expire = NULL, *min = NULL;
	static uc *p = NULL;
	static size_t delta;

	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	if (!(string = (uc *)calloc_e(string, hostmax, sizeof(uc))))
		goto __err;
	if (!(domain = (uc *)calloc_e(domain, hostmax, sizeof(uc))))
		goto __err;
	if (!(mailn = (uc *)calloc_e(mailn, hostmax, sizeof(uc))))
		goto __err;

	for (k = 0; k < acnt; ++k)
	  {
		if (! TTL_OK(ntohl(ans_array[k].resource->ttl)))
		  {
			if (STALE_OK)
				goto __stale_ok;
			printf("\e[3;31mResource record is stale (ttl:\e[m %u\e[3;02m)\e[m\r\n",
					ntohl(ans_array[k].resource->ttl));
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			continue;
		  }
		__stale_ok:
		switch(ntohs(ans_array[k].resource->type))
		  {
			case(1): /* IP address */
			if (ntohs(ans_array[k].resource->_class) == 3) /* CHAOS */
			  {
				p = ans_array[k].rdata;
				if (GetName(p, buf, string, &delta) == -1)
					goto __err;
				p += delta;
				a16 = (u16 *)p;
				printf("\e[3;02m%18s\e[m %s [%u]\r\n"
					"%18s %0o\r\n",
					"Chaos Name",
					string,
					ntohl(ans_array[k].resource->ttl),
					"Chaos Address",
					*a16);
				p += sizeof(u16);
				free(ans_array[k].name); free(ans_array[k].rdata);
				ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			  }
			else
			  {
				p = ans_array[k].rdata;
				a32 = (struct in_addr *)p;
				if ((a32_str = inet_ntoa(*a32)) == NULL)
					{ perror("GetAnswers: inet_ntoa"); goto __err; }
				printf("\e[3;02m%18s\e[m %s [%u]\r\n",
					"IPv4 Address",
					a32_str,
					ntohl(ans_array[k].resource->ttl));
				free(ans_array[k].name); free(ans_array[k].rdata);
				ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			  }
			break;
			case(2):
			p = ans_array[k].rdata;
			if (GetName(p, buf, string, &delta) == -1)
				goto __err;
			p += delta;
			printf("\e[3;02m%18s\e[m %s [%u]\r\n",
				"Name Server",
				string,
				ntohl(ans_array[k].resource->ttl));
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(5): /* Canonical name */
			p = ans_array[k].rdata;
			if (GetName(p, buf, string, &delta) == -1)
				goto __err;
			p += delta;
			printf("\e[3;02m%18s\e[m %s [%u]\r\n",
				"Canonical Name",
				string,
				ntohl(ans_array[k].resource->ttl));
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(6): /* SOA - start of authority */
			p = ans_array[k].rdata;
			if (GetName(p, buf, domain, &delta) == -1)
				goto __err;
			p += delta;
			if (GetName(p, buf, mailn, &delta) == -1)
				goto __err;
			p += delta;
			serial = (u32 *)p;
			*serial = ntohl(*serial);
			p += sizeof(u32);
			refresh = (u32 *)p;
			*refresh = ntohl(*refresh);
			p += sizeof(u32);
			retry = (u32 *)p;
			*retry = ntohl(*retry);
			p += sizeof(u32);
			expire = (u32 *)p;
			*expire = ntohl(*expire);
			p += sizeof(u32);
			min = (u32 *)p;
			*min = ntohl(*min);
			p += sizeof(u32);
			printf("\e[3;02m%18s\e[m %s\r\n"
				"\e[3;02m%18s\e[m %s\r\n"
				"\e[3;02m%18s \e[m%u\r\n"
				"\e[3;02m%18s \e[m%d\r\n"
				"\e[3;02m%18s \e[m%d\r\n"
				"\e[3;02m%18s \e[m%d\r\n"
				"\e[3;02m%18s \e[m%d\r\n"
				"\e[3;02m%18s\e[m %u\r\n",
				"domain", domain, "mail", mailn,
				"S#", *serial,
				"REFR", (signed)*refresh,
				"RETR", (signed)*retry,
				"EXP", (signed)*expire,
				"MIN", (signed)*min,
				"TTL", ntohl(ans_array[k].resource->ttl));

			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(12): /* PTR record */
			p = ans_array[k].rdata;
			if (GetName(p, buf, string, &delta) == -1)
				goto __err;
			p += delta;
			printf("\e[3;02m%18s\e[m %s [%u]\r\n",
				"Pointer",
				string,
				ntohl(ans_array[k].resource->ttl));
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(15): /* MX record */
			p = ans_array[k].rdata;
			pref = (u16 *)p;
			*pref = ntohs(*pref);
			p += sizeof(u16);
			if (GetName(p, buf, string, &delta) == -1)
				goto __err;
			p += delta;
			printf("\e[3;02m%18s\e[m %s (\e[3;02mpref\e[m %hu) [%u]\r\n",
				"Mail Exchange",
				string,
				*pref,
				ntohl(ans_array[k].resource->ttl));
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(16): /* txt record */
			printf("\e[3;02m%s\e[m\r\n", "Txt Record");
			p = ans_array[k].rdata;
			while (p < (ans_array[k].rdata + ntohs(ans_array[k].resource->len)))
			  {
				if (iscntrl(*p) && *p != '\r' && *p != '\n')
					++p;
				putchar(*p++);
			  } 
			putchar('\n');
			free(ans_array[k].name); free(ans_array[k].rdata);
			ans_array[k].name = NULL; ans_array[k].rdata = NULL;
			break;
			case(28): /* AAAA record (ipv6) */
			p = ans_array[k].rdata;
			a128 = (struct in6_addr *)p;
			if (! inet_ntop(AF_INET6, &a128->s6_addr, a128_str, INET6_ADDRSTRLEN))
				{ perror("GetAnswers: inet_ntop"); goto __err; }
			p += ntohs(ans_array[k].resource->len);
			printf("\e[3;02m%18s\e[m %s [%u]\r\n",
				"IPv6 Address",
				a128_str,
				ntohl(ans_array[k].resource->ttl));
			break;
			case(35): /* NAPTR record */
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
			printf("\e[3;02m%18s\e[m %s [%u]\r\n", 
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

	if (string != NULL) free(string);
	if (domain != NULL) free(domain);
	if (mailn != NULL) free(mailn);
	for (k = 0; k < acnt; ++k)
	  {
		if (ans_array[k].name != NULL) free(ans_array[k].name);
		if (ans_array[k].rdata != NULL) free(ans_array[k].rdata);
	  }
	return(0);

	__err:
	err = errno;
	if (string != NULL) free(string);
	if (domain != NULL) free(domain);
	if (mailn != NULL) free(mailn);
	for (k = 0; k < acnt; ++k)
	  {
		if (ans_array[k].name != NULL) free(ans_array[k].name);
		if (ans_array[k].rdata != NULL) free(ans_array[k].rdata);
	  }
	errno = err;
	return(-1);
}
