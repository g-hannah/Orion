#include "dns.h"

ssize_t
PrintInfoDNS(uc *ptr, int flag, u16 transaction_id, uc *ns)
{
	DNS_HEADER *d = NULL;
	DNS_QUESTION *q = NULL;
	uc *p = ptr;
	static int ok = 0;

	if (ptr == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }
	d = (DNS_HEADER *)ptr;
	p += sizeof(DNS_HEADER);
	printf("Questions %hu | Answers %hu | Authoritative %hu | Additional %hu\r\n",
		ntohs(d->qdcnt),
		ntohs(d->ancnt),
		ntohs(d->nscnt),
		ntohs(d->arcnt));
	printf("  Query \"");
	if (!isdigit(*p) && !isalpha(*p))
		++p;
	while (*p != 0)
	  {
		if (!isdigit(*p) && !isalpha(*p) && *p != 0x2d)
		  {
			putchar('.');
			p++;
		  }
		putchar(*p++);
	  }
	printf("\" @SERVER %s:53\r\n", ns);
	++p;
	q = (DNS_QUESTION *)p;
	if (ntohs(d->ident) == transaction_id)
		ok = 1;
	printf("  Transaction ID 0x%hx %s\r\n",
		ntohs(d->ident),
		(flag?(ok?"\e[1;02m[\e[1;32mVALID\e[m\e[1;02m]\e[m":"\e[1;02m[\e[1;31mINVALID\e[m\e[1;02m]\e[m"):""));
	printf("  FLAGS: %s %s %s %s %s %s %s  QTYPE: %s  QCLASS: %s  STATUS: %s\r\n",
		d->qr?"qr":"",
		d->aa?"aa":"",
		d->tc?"tc":"",
		d->rd?"rd":"",
		d->ra?"ra":"",
		d->ad?"ad":"",
		d->cd?"cd":"",
		GetQType(ntohs(q->qtype)),
		GetQClass(ntohs(q->qclass)),
		GetRCode(d->rcode));
	putchar('\n');
	return(0);
}
