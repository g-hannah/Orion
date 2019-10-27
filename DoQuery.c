#include "dns.h"

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

	if (12 == qtype)
	{
	}
	else
	if (35 == qtype)
	{
	}
}

ssize_t
DoQuery(uc *host, uc *ns, _atomic_ q_type, _atomic_ q_class)
{
	if (!(buf = calloc_e(buf, BUFSIZ, sizeof(uc))))
		goto __err;

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
