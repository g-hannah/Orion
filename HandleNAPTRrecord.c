#include "dns.h"

ssize_t
HandleNAPTRrecord(DNS_RRECORD *record)
{
	if (record == NULL)
	  {
		fprintf(stderr, "\e[3;31mHandleNAPTRrecord: record is NULL\e[m\r\n");
		errno = EINVAL;
		return(-1);
	  }

	static uc *p = NULL, *name = NULL;
	static size_t len, delta;
	static int hostmax;
	static NAPTR_DATA *naptr = NULL;

	naptr = (NAPTR_DATA *)record->rdata;
	len = ntohs(record->resource->len);
	printf("\e[3;02mNAPTR record\e[m\r\n\r\n");
	p = record->name;
	printf("\e[3;02mnumber\e[m ");
	while (*p != 0 && (void *)p < (void *)(record + len))
		putchar(*p++);
	printf("\r\n");
	printf("\e[3;02morder\e[m %hu\r\n", ntohs(naptr->order));
	printf("\e[3;02mpreference\e[m %hu\r\n", ntohs(naptr->pref));
	printf("\e[3;02mservices\e[m ");
	p = naptr->services;
	while (*p != 0 && (void *)p < (void *)(record + len))
		putchar(*p++);
	printf("\r\n");
	printf("\e[3;02mregex\e[m ");
	p = naptr->regex;
	while (*p != 0 && (void *)p < (void *)(record + len))
		putchar(*p++);
	printf("\r\n");
	p = naptr->replace;
	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	if (!(name = (uc *)calloc_e((uc *)name, hostmax, sizeof(uc))))
		goto __err;
	delta = 0;
	if (GetName(p, record->rdata, name, &delta) == -1)
		{ perror("HandleNAPTRrecord: GetName"); goto __err; }
	p += delta;
	printf("\e[3;02mreplacement\e[m %s", name);


	if (name != NULL) free(name);
	return(0);

	__err:
	if (name != NULL) free(name);
	return(-1);
}
