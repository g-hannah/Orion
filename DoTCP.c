#include "dns.h"

static sigjmp_buf __ALARM_ENV__;

static void
catch_sigalarm(int signo)
{
	if (signo != SIGALRM)
		return;
	fprintf(stderr, "\e[3;31mrequest timed out\e[m\r\n");
	siglongjmp(__ALARM_ENV__, 1);
}

ssize_t
DoTCP(uc *buf, size_t size, uc *ns)
{
	if (buf == NULL || size <= 0 || ns == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }

	static struct sockaddr_in s4;
	static struct sigaction n_act;
	static ssize_t ret = 0;
	static int s;
	static char tstring[50];
	static time_t seed;
	static struct tm *_time;

	memset(&n_act, 0, sizeof(n_act));
	n_act.sa_handler = catch_sigalarm;
	sigemptyset(&n_act.sa_mask);
	sigaddset(&n_act.sa_mask, SIGINT);
	sigaddset(&n_act.sa_mask, SIGQUIT);
	n_act.sa_flags = 0;
	if (sigaction(SIGALRM, &n_act, NULL) < 0)
		{ perror("do_tcp: failed to set signal handler for SIGALRM"); goto __err; }
	memset(&s4, 0, sizeof(s4));
	s4.sin_family = AF_INET;
	s4.sin_port = htons(53);
	if (inet_pton(AF_INET, ns, &s4.sin_addr.s_addr) < 0)
		{ perror("do_tcp: inet_pton"); goto __err; }
	if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		{ perror("do_tcp: socket"); goto __err; }
	if (sigsetjmp(__ALARM_ENV__, 0) != 0)
		goto __err;
	alarm(10);
	if (connect(s, (struct sockaddr *)&s4, (socklen_t)sizeof(s4)) != 0)
		{ perror("do_tcp: connect"); goto __err; }
	alarm(0);
	seed = time(NULL);
	if ((_time = localtime(&seed)) == NULL)
		goto __err;
	if (strftime(tstring, 30, "%a %d %b %Y %H:%M:%S", _time) < 0)
		goto __err;
	printf("\r\n\e[3;02mDNS Query (sent %s [TZ %s])\e[m\r\n", tstring, _time->tm_zone);
	if (PrintInfoDNS(buf, 0, getpid(), ns) == -1)
		goto __err;
	alarm(10);
	if ((ret = send_a(s, buf, size, 0)) == -1)
		{ perror("do_tcp: send_a"); goto __err; }
	alarm(0);
	alarm(10);
	if ((ret = recv_a(s, buf, BUFSIZ, 0)) == -1)
		{ perror("do_tcp: recv_a"); goto __err; }
	alarm(0);
	shutdown(s, SHUT_RDWR);
	buf[ret] = 0;
	return(ret);

	__err:
	return(-1);
}
