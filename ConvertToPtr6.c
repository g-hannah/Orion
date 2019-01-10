#include "dns.h"

ssize_t
ConvertToPtr6(uc *out, uc *in, size_t *strptr_len)
{
	if (in == NULL || out == NULL || strptr_len == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }

	static uc *tmp = NULL, *p1 = NULL, *p2 = NULL, *t = NULL;
	static int k;
	static int err;
	static size_t len;
	if (!(tmp = (uc *)calloc_e(tmp, 73, sizeof(uc))))
		goto __err;
	len = strlen((uc *)in);
	k = 0;
	/*2a03:2880:f12a:183:face:b00c:0:25de*/
	/* 		 ^  ^
	*/
	/* add in zeros where needed */
	p1 = in; p2 = in; t = tmp;

	for(;;)
	  {
		k = 0;
		while (*p1 != ':' && p1 < (in + len))
			++p1;
		if (*p1 != ':' && p1 != (in + len))
		  {
			errno = EPROTO;
			goto __err;
		  }
		if (p1 == (in + len) && p2 == (in + len))
			break;
		if ((p1 - p2) < 4)
		  {
			while (k < (4 - (p1 - p2)))
				{ *t++ = 0x30; ++k; }
			while (p2 != p1)
				*t++ = *p2++;
			if (p1 != (in + len))
				{ *t++ = *p1++; ++p2; }
		  }
		else
		  {
			while (p2 != p1)
				*t++ = *p2++;
			if (p1 != (in + len))
				{ *t++ = *p1++; ++p2; }
		  }
	  }
	
	*t = 0; /* null terminate */
	*strptr_len = strlen((uc *)tmp);
	t = (tmp + (strlen((uc *)tmp)-1));
	p1 = out;
	while (t >= tmp)
	  {
		if (*t == ':')
			--t;
		*p1++ = *t--;
		*p1++ = '.';
	  }
	t = tmp;
	if (strncpy((uc *)p1, "ip6-arpa.", 9) == NULL)
		{ perror("ConvertToPtr: strncpy "); goto __err; }
	p1 = (p1 + 9);
	*p1 = 0;
	memset(tmp, 0, 73);
	memcpy(tmp, out, strlen((uc *)out));
	memset(out, 0, strlen((uc *)out));
	if (ConvertName(out, tmp, strptr_len) == -1)
		goto __err;
	if (tmp != NULL) free(tmp);
	return(0);

	__err:
	err = errno;
	if (tmp != NULL) free(tmp);
	errno = err;
	return(-1);
}
