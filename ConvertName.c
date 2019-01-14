#include "dns.h"

ssize_t
ConvertName(uc *qname, uc *host, size_t *len)
{
	int		qidx;
	uc		*p = NULL, *q = NULL;

	p = q = host;
	qidx &= ~qidx;

	for (;;)
	  {
		while (*q != 0x2e && q < (host + strlen(host)))
			++q;
		if (q == (host + strlen(host)))
		  {
			qname[qidx++] = (q - p);
			strncpy(&qname[qidx], p, (q - p));
			qidx += (q - p);
			qname[qidx] = 0;
			break;
		  }
		qname[qidx++] = (q - p);
		strncpy(&qname[qidx], p, (q - p));
		qidx += (q - p);
		++q;
		p = q;
	  }

	*len = strlen(qname);
	return(0);
}
