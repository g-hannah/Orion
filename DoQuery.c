#include "dns.h"

#define NSEC_PER_SEC 1000000

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

		p += delta;
	}

	if (ntohs(dns->nscnt) > 0)
	{
		if (get_records(auth_cache, ntohs(dns->nscnt), p, buf, total, &delta) < 0)
			goto fail;

		p += delta;
	}

	if (ntohs(dns->arcnt) > 0)
	{
		if (get_records(additional_cache, ntohs(dns->arcnt), p, buf, total, &delta) < 0)
			goto fail;

		p += delta;
	}

	return 0;

	fail:
	return -1;
}

ssize_t
DoQuery(uc *host, uc *ns, _atomic_ q_type, _atomic_ q_class)
{
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
