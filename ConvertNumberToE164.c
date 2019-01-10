#include "dns.h"

ssize_t
ConvertNumberToE164(uc *target, uc *number, size_t *targetlen)
{
	if (target == NULL || number == NULL || targetlen == NULL)
	  {
		errno = EINVAL;
		fprintf(stderr, "ConvertNumberToE164: %s\r\n", strerror(errno));
		errno = EINVAL;
		return(-1);
	  }

	static uc *tmp = NULL, *p = NULL, *t = NULL;
	static size_t numlen;
	static int k;

	if (!(tmp = (uc *)calloc_e(tmp, 256, sizeof(char))))
		goto __err;

	numlen = strlen(number);
	p = (number + (numlen - 1));
	t = tmp;

	while (p >= number)
	  {
		*t++ = *p--;
		*t++ = 0x2e;
	  }

	sprintf(t, "%s", "e164.arpa");
	t += strlen("e164.arpa");
	*t = 0;

	if (strncpy(target, tmp, strlen(tmp)) == NULL)
		{ perror("ConvertNumberToE164"); goto __err; }

	*targetlen = strlen(tmp);

	if (tmp != NULL) free(tmp);
	return(0);

	__err:
	if (tmp != NULL) free(tmp);
	return(-1);
}
