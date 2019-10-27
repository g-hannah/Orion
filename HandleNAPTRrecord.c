#include "dns.h"

int
handle_nptr_record(DNS_RRECORD *record)
{
	assert(record);

	char *p;
	char *name;
	size_t len, delta;
	int hostmax;
	NAPTR_DATA *naptr = NULL;

	naptr = (NAPTR_DATA *)record->rdata;

	len = ntohs(record->resource->len);
	fprintf(stdout, "\e[3;02mNAPTR record\e[m\n\n");
	p = record->name;
	fprintf(stdout, "\e[3;02mnumber\e[m ");
	fprintf(stdout, "%.*s\n", (int)len, p);

	fprintf(stdout, "\e[3;02morder\e[m %hu\n", ntohs(naptr->order));
	fprintf(stdout, "\e[3;02mpreference\e[m %hu\n", ntohs(naptr->pref));
	fprintf(stdout, "\e[3;02mservices\e[m %s\n", naptr->services);
	fprintf(stdout, "%s\n", naptr->services);
	fprintf(stdout, "\e[3;02mregex\e[m %s\n", naptr->regex);
	p = naptr->replace;

	if (!(name = calloc_e(name, hostmax, sizeof(uc))))
		goto fail;

	delta = 0;
	if (get_name(p, record->rdata, name, &delta) < 0)
		goto fail;

	p += delta;
	fprintf(stdout, "\e[3;02mreplacement\e[m %s\n", name);

	free(name);
	name = NULL;

	return 0;

	fail:

	if (name)
	{
		free(name);
		name = NULL;
	}

	return -1;
}
