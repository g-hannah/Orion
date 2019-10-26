#ifndef ORION_H
#define ORION_H 1

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DNS_PORT_NR 53
#define DNS_MAX_TIME_WAIT 5

#define LOCAL_DNS "127.0.1.1"
#define LOCAL_DNS2 "127.0.0.1"
#define GOOGLE_DNS "8.8.8.8"
#define GOOGLE_DNS2 "8.8.4.4"

#define SECS_PER_WEEK (60*60*24*7)

#define TMP_BUF_DEFAULT_SIZE 1024

#define TTL_OK(x) ((x) < SECS_PER_WEEK)
#define __ALIGN_SIZE(s, _s) (((s) + ((_s) - 1)) & ~((_s) - 1))
#define __ALIGN_DEF(s) __ALIGN_SIZE(s, 16)

#define clear_struct(s) memset((s), 0, sizeof((*s)))

typedef unsigned char uc;
typedef unsigned int ui;
typedef unsigned short us;
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

enum QTYPE
{
	QTYPE_A = 1,
	QTYPE_NS = 2,
	QTYPE_CNAME = 5,
	QTYPE_SOA = 6,
	QTYPE_PTR = 12,
	QTYPE_MX = 15,
	QTYPE_TXT = 16,
	QTYPE_RP = 17,
	QTYPE_AFSDB = 18,
	QTYPE_SIG = 24,
	QTYPE_KEY = 25,
	QTYPE_AAAA = 28,
	QTYPE_LOC = 29,
	QTYPE_SRV = 33,
	QTYPE_NAPTR = 35,
	QTYPE_KX = 36,
	QTYPE_CERT = 37,
	QTYPE_DNAME = 39,
	QTYPE_OPT = 41,
	QTYPE_APL = 42,
	QTYPE_DS = 43,
	QTYPE_SSHFP = 44,
	QTYPE_IPSECKEY = 45,
	QTYPE_RRSIG = 46,
	QTYPE_NSEC = 47,
	QTYPE_DNSKEY = 48,
	QTYPE_DHCID = 49,
	QTYPE_NSEC3 = 50,
	QTYPE_NSEC3PARAM = 51,
	QTYPE_TLSA = 52,
	QTYPE_HIP = 55,
	QTYPE_CDS = 59,
	QTYPE_CDNSKEY = 60,
	QTYPE_OPENPGPGKEY = 61,
	QTYPE_TKEY = 249,
	QTYPE_TSIG = 250, /* ttl = 0; class = any; */
	QTYPE_IXFR = 251,
	QTYPE_AXFR = 252,
	QTYPE_ANY = 255,
	QTYPE_URI = 256,
	QTYPE_TA = 32768,
	QTYPE_DLV = 32769
};

typedef enum QTYPE DNS_QTYPE;

enum QCLASS
{
	QCLASS_INET = 1,
	QCLASS_CHAOS = 3,
	QCLASS_HESIOD = 4,
	QCLASS_NONE = 254,
	QCLASS_ALL = 255
};

typedef enum QCLASS DNS_QCLASS;

struct HEADER
{
	us ident;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	us rd:1; /* recursion desired */
	us tc:1; /* response truncated */
	us aa:1; /* authoritative answers */
	us opcode:4;
	us qr:1; /* query / response */
	us rcode:4;
	us cd:1;  /* checking disabled */
	us ad:1; /* authentic data */
	us z:1; /* reserved; zero */
	us ra:1; /* recursion available */
#elif __BYTE_ORDER == __BIG_ENDIAN
	us qr:1;
	us opcode:4;
	us aa:1;
	us tc:1;
	us rd:1;
	us ra:1;
	us z:1;
	us ad:1;
	us cd:1;
	us rcode:4;
#else
# error "please adjust <bits/endian.h>"
#endif
	us qdcnt;
	us ancnt;
	us nscnt;
	us arcnt;
};

typedef struct HEADER DNS_HEADER;

struct QUESTION
{
	us qtype;
	us qclass;
};

typedef struct QUESTION DNS_QUESTION;

struct QUERY
{
	uc *name;
	struct QUESTION *q;
};

typedef struct QUERY DNS_QUERY;

struct RDATA
{
	us type;
	us _class;
	u32 ttl;
	us len;
} __attribute__ ((__packed__));

typedef struct RDATA DNS_RDATA;

struct RRECORD
{
	uc *name;
	struct RDATA *resource;
	uc *rdata;
};

typedef struct RRECORD DNS_RRECORD;

struct NAPTR_DATA
{
	us order;
	us pref;
	uc *flags;
	uc *services;
	uc *regex;
	uc *replace;
} __attribute__ ((__packed__));

typedef struct NAPTR_DATA NAPTR_DATA;



/* __START_FUNC_DECS__ */
ssize_t ConvertName(uc *, uc *, size_t *) __THROW __nonnull ((1,2,3)) __wur;
ssize_t ConvertToPtr(uc *, uc *, size_t *) __THROW __nonnull ((1,2,3)) __wur;
ssize_t ConvertToPtr6(uc *, uc *, size_t *) __THROW __nonnull ((1,2,3)) __wur;
ssize_t ConvertNumberToE164(uc *, uc *, size_t *) __THROW __nonnull ((1,2,3)) __wur;
ssize_t GetName(uc *, uc *, uc *, size_t *) __THROW __nonnull ((1,2,3,4)) __wur;
ssize_t GetAnswers(DNS_RRECORD[], u16, uc *, _atomic_) __THROW __nonnull ((1,3)) __wur;
ssize_t GetRecords(DNS_RRECORD[], u16, uc *, uc *, size_t, size_t *)
	__THROW __nonnull ((1,3,4,6)) __wur;
uc *GetQClass(us) __THROW __wur;
uc *GetQType(us) __THROW __wur;
uc *GetOpCode(us) __THROW __wur;
uc *GetRCode(us) __THROW __wur;
ssize_t DoQuery(uc *, uc *, _atomic_, _atomic_) __THROW __nonnull ((1,2)) __wur;
void Usage(void) __attribute__ ((__noreturn__));
ssize_t ResolveQType(const uc *, _atomic_ *) __THROW __nonnull ((1,2)) __wur;
ssize_t PrintInfoDNS(uc *, int, u16, uc *) __THROW __nonnull ((1,4)) __wur;
ssize_t DoTCP(uc *, size_t, uc *) __THROW __nonnull ((1,3)) __wur;
ssize_t DoUDP(uc *, size_t, uc *) __THROW __nonnull ((1,3)) __wur;
ssize_t HandleNAPTRrecord(DNS_RRECORD *) __THROW __nonnull ((1)) __wur;
/* __END_FUNC_DECS__ */

/*wrappers*/
void *calloc_e(void *, size_t, size_t) __attribute__ ((alloc_size(2,3)));
void *malloc_e(void *, size_t) __attribute__ ((alloc_size(2)));
int socket_e(int, int, int, int);
/*a == 'all' */
ssize_t send_a(int, uc *, size_t, int) __THROW __nonnull ((2)) __wur;
ssize_t recv_a(int, uc *, size_t, int) __THROW __nonnull ((2)) __wur;
ssize_t sendto_a(int, uc *, size_t, int, struct sockaddr *, socklen_t) __THROW __nonnull ((2)) __wur;
ssize_t recvfrom_a(int, uc *, size_t, int, struct sockaddr *, socklen_t *) __THROW __nonnull ((2,5,6)) __wur;

int decode_name(uc *, uc *, uc *, size_t) __nonnull((1,2,3)) __wur;






















#endif /* !defined ORION_H */
