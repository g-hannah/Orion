#include "dns.h"

ssize_t
GetRecords(DNS_RRECORD array[], u16 cnt, uc *ptr, uc *buf, size_t size, size_t *delta)
{
	static int k, hostmax = 0;
	static uc *p = NULL;

	if (array == NULL || cnt <= 0 || buf == NULL || ptr == NULL || size <= 0 || delta == NULL)
	  {
		fprintf(stderr, "\e[1;02m\e[3;31m%s%s\e[m\r\n",
	(array==NULL?"array":cnt<=0?"cnt":buf==NULL?"buf":ptr==NULL?"ptr":size<=0?"size":"delta"),
(array==NULL?"==NULL":cnt<=0?"<=0":buf==NULL?"==NULL":ptr==NULL?"==NULL":size<=0?"<=0":"NULL"));
		errno = EINVAL;
		return(-1);
	  }
	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	*delta &= ~(*delta); p = ptr;

	for (k = 0; k < cnt; ++k)
	  {
		if (!(array[k].name = (uc *)calloc_e(array[k].name, hostmax, sizeof(uc))))
			goto __err;
		if (GetName(p, buf, array[k].name, delta) == -1)
			goto __err;
		p += *delta;
		if (!(array[k].resource = (DNS_RDATA *)malloc_e(array[k].resource, sizeof(DNS_RDATA))))
			goto __err;
		if (memcpy(array[k].resource, p, sizeof(DNS_RDATA)) == NULL)
			{ perror("GetRecords: memcpy"); goto __err; }
		p += sizeof(DNS_RDATA);
		if (!(array[k].rdata = (uc *)calloc_e(array[k].rdata, ntohs(array[k].resource->len)+1, sizeof(uc))))
			goto __err;
		if (memcpy(array[k].rdata, p, ntohs(array[k].resource->len)) == NULL)
			{ perror("GetRecords: memcpy"); goto __err; }
		p += ntohs(array[k].resource->len);
	  }

	*delta = (p - ptr);
	return(0);

	__err:
	return(-1);
}
