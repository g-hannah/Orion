#include "dns.h"

static int err;

void *
calloc_e(void *p, size_t size, size_t type)
{
	if (!(p = calloc(size, type)))
	  {
		err = errno;
		fprintf(stderr, "calloc: ");
		errno = err;
		return(NULL);
	  }
	else
		return(p);
}

void *
malloc_e(void *p, size_t type)
{
	if (!(p = malloc(type)))
	  {
		err = errno;
		fprintf(stderr, "malloc: ");
		errno = err;
		return(NULL);
	  }
	else
		return(p);
}

int
socket_e(int s, int domain, int type, int protocol)
{
	if ((s = socket(domain, type, protocol)) < 0)
	  {
		err = errno;
		fprintf(stderr, "socket: ");
		errno = err;
		return(-1);
	  }
	else
		return(s);
}

ssize_t
send_a(int sock, uc *buf, size_t size, int flags)
{
	size_t tosend = size, total = 0;
	ssize_t ret = 0;
	uc *p = buf;

	while (tosend > 0 && (ret = send(sock, p, tosend, flags) > 0))
	  {
		if (ret < 0)
		  {
			err = errno;
			fprintf(stderr, "send: ");
			errno = err;
			return(-1);
		  }
		tosend -= ret;
		p += ret;
		total += ret;
	  }
	return(total);
}

ssize_t
recv_a(int sock, uc *buf, size_t size, int flags)
{
	ssize_t ret = 0;
	size_t total = 0;
	uc *p = buf;

	while ((ret = recv(sock, p, size, flags) > 0))
	  {
		if (ret < 0)
		  {
			perror("recv");
			return(-1);
		  }
		p += ret;
		total += ret;
	  }
	return(total);
}

ssize_t
recvfrom_a(int sock, uc *buf, size_t size, int flags, struct sockaddr *sa, socklen_t *ss)
{
	ssize_t ret = 0, total = 0;
	uc *p = buf;

	while ((ret = recvfrom(sock, p, size, flags, sa, ss)) > 0)
	  {
		if (ret < 0)
		  {
			perror("recvfrom");
			return(-1);
		  }
		p += ret;
		total += ret;
	  }
	return(total);
}

ssize_t
sendto_a(int sock, uc *buf, size_t size, int flags, struct sockaddr *sa, socklen_t ss)
{
	size_t tosend = size;
	ssize_t ret = 0, total = 0;
	uc *p = buf;

	while (tosend > 0 && (ret = sendto(sock, p, tosend, flags, sa, ss)) > 0)
	  {
		if (ret < 0)
		  {
			err = errno;
			fprintf(stderr, "sendto: ");
			errno = err;
			return(-1);
		  }
		tosend -= ret;
		p += ret;
		total += ret;
	  }
	return(total);
}
