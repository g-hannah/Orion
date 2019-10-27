#include "dns.h"

void *
calloc_e(void *p, size_t size, size_t type)
{
	if (!(p = calloc(size, type)))
	{
		fprintf(stderr, "calloc_e: failed to allocate memory (%s)\n", strerror(errno));
		return NULL;
	}
	else
	{
		return p;
	}
}

void *
malloc_e(void *p, size_t type)
{
	if (!(p = malloc(type)))
	{
		fprintf(stderr, "malloc_e: failed to allocate memory (%s)\n", strerror(errno));
		return NULL;
	}
	else
	{
		return p;
	}
}

int
socket_e(int s, int domain, int type, int protocol)
{
	if ((s = socket(domain, type, protocol)) < 0)
	{
		err = errno;
		fprintf(stderr, "socket_e: failed to open socket (%s)\n", strerror(errno));
		errno = err;
		return -1;
	}
	else
	{
		return s;
	}
}

ssize_t
send_a(int sock, char *buf, size_t size, int flags)
{
	size_t tosend = size, total = 0;
	ssize_t ret = 0;
	char *p = buf;

	while (tosend > 0 && (ret = send(sock, p, tosend, flags)))
	{
		if (ret < 0)
		{
			fprintf(stderr, "send_a: failed to send data (%s)\n", strerror(errno));
			return -1;
		}

		tosend -= ret;
		p += ret;
		total += ret;
	}

	return total;
}

ssize_t
recv_a(int sock, char *buf, size_t size, int flags)
{
	ssize_t ret = 0;
	size_t total = 0;
	char *p = buf;

	while ((ret = recv(sock, p, size, flags)))
	{
		if (ret < 0)
		{
			fprintf(stderr, "recv_a: failed to receive data (%s)\n", strerror(errno));
			return -1;
		}

		p += ret;
		total += ret;
	}

	return total;
}

ssize_t
recvfrom_a(int sock, char *buf, size_t size, int flags, struct sockaddr *sa, socklen_t *ss)
{
	ssize_t ret = 0;
	ssize_t total = 0;
	char *p = buf;

	while ((ret = recvfrom(sock, p, size, flags, sa, ss)))
	{
		if (ret < 0)
		{
			fprintf(stderr, "recvfrom_a: failed to receive data (%s)\n", strerror(errno));
			return -1;
		}

		p += ret;
		total += ret;
	}

	return total;
}

ssize_t
sendto_a(int sock, char *buf, size_t size, int flags, struct sockaddr *sa, socklen_t ss)
{
	size_t tosend = size;
	size_t total = 0;
	ssize_t ret = 0;
	char *p = buf;

	while (tosend > 0 && (ret = sendto(sock, p, tosend, flags, sa, ss)))
	{
		if (ret < 0)
		{
			fprintf(stderr, "sendto_a: failed to send data (%s)\n", strerror(errno));
			return -1;
		}

		tosend -= ret;
		p += ret;
		total += ret;
	}

	return total;
}
