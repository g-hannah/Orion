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
DHCP_GetNS(uc *ns)
{
	static DHCP_MSG *dhcp = NULL;
	static uc *buf = NULL, *p = NULL;
	static int s, opt;
	static struct ifreq ifr;
	static struct ether_addr eaddr;
	static struct sockaddr_in s4;
	static struct in_addr *in4;
	static uc *ether_str = NULL, ipv4_str[INET_ADDRSTRLEN];
	static size_t tosend;
	static struct sigaction n_act;

	if (ns == NULL)
	  {
		errno = EINVAL;
		return(-1);
	  }

	memset(&n_act, 0, sizeof(n_act));
	sigemptyset(&n_act.sa_mask);
	sigaddset(&n_act.sa_mask, SIGINT);
	sigaddset(&n_act.sa_mask, SIGQUIT);
	n_act.sa_flags = 0;
	n_act.sa_handler = catch_sigalarm;
	if (sigaction(SIGALRM, &n_act, NULL) < 0)
		{ perror("DHCP_GetNS: failed to set signal handler for SIGALRM"); goto __err; }
	
	if (!(buf = (uc *)calloc_e(buf, BUFSIZ, sizeof(uc))))
		goto __err;

	printf("\e[3;02mUsing DHCP to obtain primary/secondary DNS servers\e[m\r\n");
	memset(&s4, 0, sizeof(s4));
	dhcp = (DHCP_MSG *)buf;
	dhcp->op = htons(DHCP_REQUEST);
	dhcp->htype = htons(DHCP_HTYPE_ETH);
	dhcp->hlen = htons(ETH_ALEN);
	dhcp->hops = 0;
	dhcp->transaction_id = htons(getpid());
	dhcp->seconds = 10;
	dhcp->flags &= ~dhcp->flags;
	dhcp->your_ipv4 &= ~dhcp->your_ipv4;
	dhcp->server_ipv4 &= ~dhcp->server_ipv4;
	dhcp->router_ipv4 &= ~dhcp->router_ipv4;
	memset(dhcp->server_hname, 0, 64);
	memset(dhcp->boot_filename, 0, 128);
	p = &buf[sizeof(DHCP_MSG)];
	*p++ = 0x6; /* DNS server option */
	*p++ = 0xff; /* End of DHCP options marker */
	*p = 0; /* NULL terminate */
	s4.sin_family = AF_INET;
	s4.sin_port = htons(67);
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, "wlp2s0", 6);

	printf("\e[3;00mSending DHCP request for local DNS server\e[m\r\n");
	if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
		{ perror("DHCP_GetNS: socket"); goto __err; }

	/* get hardware address */
	if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0)
		{ perror("DHCP_GetNS: ioctl"); goto __err; }
	memcpy(dhcp->client_hwd, ifr.ifr_ifru.ifru_hwaddr.sa_data, sizeof(eaddr));
	
	/* get ip address */
	if (ioctl(s, SIOCGIFADDR, &ifr) < 0)
		{ perror("DHCP_GetNS: ioctl"); goto __err; }
	memcpy(&s4, &ifr.ifr_ifru.ifru_addr, sizeof(s4)); 
	memcpy(&dhcp->client_ipv4, &s4.sin_addr.s_addr, sizeof(s4.sin_addr.s_addr));

	/* get broadcast address */
	if (ioctl(s, SIOCGIFBRDADDR, &ifr) < 0)
		{ perror("DHCP_GetNS: ioctl"); goto __err; }
	if (memcpy(&s4, &ifr.ifr_ifru.ifru_broadaddr, sizeof(s4)) == NULL)
		{ perror("DHCP_GetNS: memcpy"); goto __err; }

	opt = 1;
	if (setsockopt(s, SOL_SOCKET, SO_BROADCAST, &opt, (socklen_t)sizeof(opt)) < 0)
		{ perror("DHCP_GetNS: socksetopt"); goto __err; }
	tosend = (sizeof(DHCP_MSG)+2);
	if (sendto_a(s, buf, tosend, 0, (struct sockaddr *)&s4, (socklen_t)sizeof(s4)) == -1)
		goto __err;
	if (sigsetjmp(__ALARM_ENV__, 1) != 0)
		goto __err;
	alarm(15);
	if (recv(s, buf, BUFSIZ, 0) == -1)
		goto __err;
	alarm(0);
	p = &buf[sizeof(DHCP_MSG)];
	++p;
	in4 = (struct in_addr *)p;
	in4->s_addr = ntohl(in4->s_addr);
	if (inet_ntop(AF_INET, &in4->s_addr, ipv4_str, INET_ADDRSTRLEN) == NULL)
		{ perror("inet_ntop"); goto __err; }
	printf("\e[3;02mfound DNS server @%s\e[m\r\n", ipv4_str);
	memcpy(ns, ipv4_str, INET_ADDRSTRLEN);
	goto __err; /* for testing */

	__err:
	if (buf != NULL) free(buf);
	return(-1);
	
}
