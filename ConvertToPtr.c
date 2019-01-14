#include "dns.h"

ssize_t
ConvertToPtr(uc *name, uc *host, size_t *qnamelen)
{
	if (name == NULL || host == NULL)
	  {
		errno == EINVAL;
		return(-1);
	  }

	static int err = 0, i = 0, hostmax = 0;
	uc _1[4], _2[4], _3[4], _4[4];
	uc *ptr = NULL, *tmp = NULL;
	size_t hlen = strlen((uc *)host);

	if ((hostmax = sysconf(_SC_HOST_NAME_MAX)) == 0)
		hostmax = 256;
	if (hlen >= hostmax)
	  { errno = ENAMETOOLONG; goto __err; }
	if ((tmp = (uc *)calloc_e((uc *)tmp, hostmax, sizeof(uc))) == NULL)
		goto __err;

	host[hlen++] = '.';
	ptr = host;
	while (*ptr != '.' && ptr < (host+hlen))
		_1[i++] = *ptr++;
	_1[i] = 0;
	i = 0;
	++ptr;
	while (*ptr != '.' && ptr < (host+hlen))
		_2[i++] = *ptr++;
	_2[i] = 0;
	i = 0;
	++ptr;
	while (*ptr != '.' && ptr < (host+hlen))
		_3[i++] = *ptr++;
	_3[i] = 0;
	i = 0;
	++ptr;
	while (*ptr != '.' && ptr < (host+hlen+1))
		_4[i++] = *ptr++;
	_4[i] = 0;
	i = 0;
	snprintf((uc *)tmp, hostmax, "%s.%s.%s.%s.in-addr.arpa", _4, _3, _2, _1);
	size_t tlen = strlen((uc *)_1)+1+strlen((uc *)_2)+1+strlen((uc *)_3)+1+strlen((uc *)_4)+1+strlen("in-addr.arpa");
	tmp[tlen++] = '.';
	tmp[tlen] = 0;
	int cnt = 0, start = 0, nidx = 0, k = 0;
	size_t len = strlen((uc *)tmp);
/* 31.29.182.80.in-addr.arpa
 *
 */
	for (i = 0; i < len; ++i)
	  {
		if (tmp[i] == '.')
		  {
			start = (i-cnt);
			name[nidx++] = cnt;
			for (k = 0; k < cnt; ++k)
				name[nidx++] = tmp[start++];
			cnt = 0;
			continue;
		  }
		++cnt;
	  }
	name[nidx] = 0;
	*qnamelen = nidx;
	if (tmp != NULL) free(tmp);
	return(0);

	__err:
	err = errno;
	if (tmp != NULL) free(tmp);
	errno = err;
	return(-1);
}
