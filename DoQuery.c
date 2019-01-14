#include "dns.h"

ssize_t
DoQuery(uc *host, uc *ns, _atomic_ q_type, _atomic_ q_class)
{
	static u16 transaction_id;
	static uc *buf = NULL, *qname = NULL, *p = NULL, *e164 = NULL;
	static int i, err, z, __USED_TCP = 0, hostmax = 0;
	static DNS_RRECORD answers[20], auth[20], addit[20];
	static DNS_HEADER *dns = NULL;
	static DNS_QUESTION *q = NULL;
	static struct timespec t1, t2;
	static size_t qnamelen, tosend, trcvd, delta;
	static double diff;
	static int V6_PTR = 0;

	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	if (!(buf = calloc_e(buf, BUFSIZ, sizeof(uc))))
		goto __err;
	for (z = 0; z < 20; ++z)
	  {
		answers[z].name = NULL;
		answers[z].rdata = NULL;
		auth[z].name = NULL;
		auth[z].rdata = NULL;
		addit[z].name = NULL;
		addit[z].rdata = NULL;
	  }

	dns = (DNS_HEADER *)buf;
	qname = &buf[sizeof(DNS_HEADER)];
	dns->ident = htons(getpid());
	transaction_id = ntohs(dns->ident);
	dns->qr = 0;
	dns->opcode = 0;
	dns->aa = 0;
	dns->tc = 0;
	dns->rd = 1;
	dns->ra = 0;
	dns->z = 0;
	dns->ad = 0;
	dns->cd = 1;
	dns->rcode = 0;
	dns->qdcnt = htons(1);
	dns->ancnt = 0;
	dns->nscnt = 0;
	dns->arcnt = 0;
	if (q_type == 12) /* PTR record */
	  {
		for (i = 0; i < strlen(host); ++i)
		  {
			if (isalpha(host[i]))
				{ V6_PTR = 1; break; }
		  }
		if (!V6_PTR)
		  {
			if (ConvertToPtr(qname, host, &qnamelen) == -1)
		  	  {
				goto __err;
		  	  }
		
		  }
		else
		  {
			if (ConvertToPtr6(qname, host, &qnamelen) == -1)
			  {
				goto __err;
			  }
		  }
	  }
	else if (q_type == 35) /* NAPTR record */
	  {
		if (!(e164 = (uc *)calloc_e(e164, hostmax, sizeof(char))))
			goto __err;
		if (ConvertNumberToE164(e164, host, &qnamelen) == -1)
			{ perror("DoQuery: ConvertNumberToE164"); goto __err; }
		if (ConvertName(qname, e164, &qnamelen) == -1)
			{ perror("DoQuery: ConvertName"); goto __err; }
	  }
	else
	  {
		if (ConvertName(qname, host, &qnamelen) == -1)
		  {
			goto __err;
		  }
	  }

	q = (DNS_QUESTION *)&buf[sizeof(DNS_HEADER)+qnamelen+1];
	q->qtype = htons(q_type);
	q->qclass = htons(q_class);

	tosend = (sizeof(DNS_HEADER)+qnamelen+1+sizeof(DNS_QUESTION));
	trcvd = 0;
	memset(&t1, 0, sizeof(t1));
	memset(&t2, 0, sizeof(t2));
	if (clock_gettime(CLOCK_REALTIME, &t1) < 0)
		{ perror("doquery: clock_gettime"); goto __err; }
	if (q_type == 252) /* axfr */
	  {
		if ((trcvd = DoTCP(buf, tosend, ns)) == -1)
			goto __err;
		__USED_TCP = 1;
	  }
	else
	  {
		if ((trcvd = DoUDP(buf, tosend, ns)) == -1)
			goto __err;
	  }
	if (clock_gettime(CLOCK_REALTIME, &t2) < 0)
		{ perror("doquery: clock_gettime"); goto __err; }
	diff = ((double)(((double)t2.tv_nsec/1000000) - ((double)t1.tv_nsec/1000000)));

	printf("\e[3;02mDNS Response (%3.2lf ms; Protocol %s)\e[m\r\n",
			diff,
			(__USED_TCP==1?"TCP":"UDP"));

	dns = (DNS_HEADER *)buf;
	p = buf;
	if (PrintInfoDNS(p, 1, transaction_id, ns) == -1)
		{ perror("PrintInfoDNS"); goto __err; }


			/* Extract the DNS Records */

	p = &buf[sizeof(DNS_HEADER)+qnamelen+1+sizeof(DNS_QUESTION)];
	if (ntohs(dns->ancnt) > 0)
	  {
		if (GetRecords(answers, ntohs(dns->ancnt), p, buf, trcvd, &delta) == -1)
			{ perror("GetRecords"); goto __err; }
		p += delta;
	  }
	if (ntohs(dns->nscnt) > 0)
	  {
		if (GetRecords(auth, ntohs(dns->nscnt), p, buf, trcvd, &delta) == -1)
			goto __err;
		p += delta;
	  }
	if (ntohs(dns->arcnt) > 0)
	  {
		if (GetRecords(addit, ntohs(dns->arcnt), p, buf, trcvd, &delta) == -1)
			goto __err;
		p += delta;
	  }

			/* Print the DNS Resource Records */

	if (ntohs(dns->ancnt) > 0)
	  {
		printf("\e[1;02m\e[3;32m\tANSWER RESOURCE RECORDS\e[m\r\n");
		if (GetAnswers(answers, ntohs(dns->ancnt), buf, q_type) == -1)
			goto __err;
	  }
	if (ntohs(dns->nscnt) > 0)
	  {
		printf("\e[1;02m\e[3;32m\tAUTHORITATIVE RESOURCE RECORDS\e[m\r\n");
		if (GetAnswers(auth, ntohs(dns->nscnt), buf, q_type) == -1)
			goto __err;
	  }
	if (ntohs(dns->arcnt) > 0)
	  {
		printf("\e[1;02m\e[3;32m\tADDITIONAL RESOURCE RECORDS\e[m\r\n");
		if (GetAnswers(addit, ntohs(dns->arcnt), buf, q_type) == -1)
			goto __err;
	  }

	if (buf != NULL) free(buf);
	return(0);

	__err:
	err = errno;
	if (buf != NULL) free(buf);
	errno = err;
	return(-1);
}
