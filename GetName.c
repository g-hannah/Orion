#include "dns.h"

ssize_t
GetName(uc *rcvd, uc *buf, uc *target, size_t *delta)
{
	static int i, offset;
	static size_t len, delt;
	static uc *start = NULL, *p = NULL;
	static _atomic_ jmp_fl;

/* blah3com0blahblahblahblahblahblahblah3www6google[192][4] */
	if (rcvd == NULL || buf == NULL || target == NULL || delta == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }

	start = (uc *)rcvd; jmp_fl = 0; offset = 0; len = 0; delt = 0;

	for (p = (uc *)rcvd; *p != 0; ++p)
	  {
		if (*p >= 0xc0) // >= 192
		  {
			offset = ((*p) * 256) + *(p+1) - (192*256);
			p = (uc *)(buf + offset);
			jmp_fl = 1;
			offset = 0;
		  }
		target[len++] = *p;
		if (!jmp_fl)
			++delt;
	  }
	if (jmp_fl == 1)
		{ p = (start + delt); ++p; }
	++p;
	*delta = (p - start);

	/* convert to normal format */
	for (i = 0; i < len; ++i)
	  {
		target[i] = target[i+1];
		if (!isalpha(target[i]) && !isdigit(target[i]) && target[i] != '-')
			target[i] = '.';
	  }
	i = 0;
	/*while (target[0] == '.')
	  {
		for (i = 0; i < (len-1); ++i)
			target[i] = target[i+1];
		--len;
		target[len] = 0;
	  }
	while (target[len-1] == '.')
	  {
		target[--len] = 0;
	  }*/
	target[len] = 0;
	jmp_fl = 0;
	return(0);
}
