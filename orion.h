#ifndef ORION_H
#define ORION_H 1

#include "buffer.h"
#include "cache.h"

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
#define __ALIGN_DEFAULT(s) __ALIGN_SIZE(s, 16)

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
	DNS_QTYPE_A = 1,
#define DNS_QTYPE_A DNS_QTYPE_A
	DNS_QTYPE_NS = 2,
#define DNS_QTYPE_NS DNS_QTYPE_NS
	DNS_QTYPE_CNAME = 5,
#define DNS_QTYPE_CNAME DNS_QTYPE_CNAME
	DNS_QTYPE_SOA = 6,
#define DNS_QTYPE_SOA DNS_QTYPE_SOA
	DNS_QTYPE_PTR = 12,
#define DNS_QTYPE_PTR DNS_QTYPE_PTR
	DNS_QTYPE_MX = 15,
#define DNS_QTYPE_MX DNS_QTYPE_MX
	DNS_QTYPE_TXT = 16,
#define DNS_QTYPE_TXT DNS_QTYPE_TXT
	DNS_QTYPE_RP = 17,
#define DNS_QTYPE_RP DNS_QTYPE_RP
	DNS_QTYPE_AFSDB = 18,
	DNS_QTYPE_SIG = 24,
#define DNS_QTYPE_SIG DNS_QTYPE_SIG
	DNS_QTYPE_KEY = 25,
#define DNS_QTYPE_KEY DNS_QTYPE_KEY
	DNS_QTYPE_AAAA = 28,
#define DNS_QTYPE_AAAA DNS_QTYPE_AAAA
	DNS_QTYPE_LOC = 29,
#define DNS_QTYPE_LOC DNS_QTYPE_LOC
	DNS_QTYPE_SRV = 33,
#define DNS_QTYPE_SRV DNS_QTYPE_SRV
	DNS_QTYPE_NAPTR = 35,
#define DNS_QTYPE_NAPTR DNS_QTYPE_NAPTR
	DNS_QTYPE_KX = 36,
#define DNS_QTYPE_KX DNS_QTYPE_KX
	DNS_QTYPE_CERT = 37,
#define DNS_QTYPE_CERT DNS_QTYPE_CERT
	DNS_QTYPE_DNAME = 39,
#define DNS_QTYPE_DNAME DNS_QTYPE_DNAME
	DNS_QTYPE_OPT = 41,
#define DNS_QTYPE_OPT DNS_QTYPE_OPT
	DNS_QTYPE_APL = 42,
#define DNS_QTYPE_APL DNS_QTYPE_APL
	DNS_QTYPE_DS = 43,
#define DNS_QTYPE_DS DNS_QTYPE_DS
	DNS_QTYPE_SSHFP = 44,
#define DNS_QTYPE_SSHFP DNS_QTYPE_SSHFP
	DNS_QTYPE_IPSECKEY = 45,
#define DNS_QTYPE_IPSECKEY DNS_QTYPE_IPSECKEY
	DNS_QTYPE_RRSIG = 46,
#define DNS_QTYPE_RRSIG DNS_QTYPE_RRSIG
	DNS_QTYPE_NSEC = 47,
#define DNS_QTYPE_NSEC DNS_QTYPE_NSEC
	DNS_QTYPE_DNSKEY = 48,
#define DNS_QTYPE_DNSKEY DNS_QTYPE_DNSKEY
	DNS_QTYPE_DHCID = 49,
#define DNS_QTYPE_DHCID DNS_QTYPE_DHCID
	DNS_QTYPE_NSEC3 = 50,
#define DNS_QTYPE_NSEC3 DNS_QTYPE_NSEC3
	DNS_QTYPE_NSEC3PARAM = 51,
#define DNS_QTYPE_NSEC3PARAM DNS_QTYPE_NSEC3PARAM
	DNS_QTYPE_TLSA = 52,
#define DNS_QTYPE_TLSA DNS_QTYPE_TLSA
	DNS_QTYPE_HIP = 55,
#define DNS_QTYPE_HIP DNS_QTYPE_HIP
	DNS_QTYPE_CDS = 59,
#define DNS_QTYPE_CDS DNS_QTYPE_CDS
	DNS_QTYPE_CDNSKEY = 60,
#define DNS_QTYPE_CDNSKEY DNS_QTYPE_CDNSKEY
	DNS_QTYPE_OPENPGPGKEY = 61,
#define DNS_QTYPE_OPENPGPKEY DNS_QTYPE_OPENPGPKEY
	DNS_QTYPE_TKEY = 249,
#define DNS_QTYPE_TKEY DNS_QTYPE_TKEY
	DNS_QTYPE_TSIG = 250, /* ttl = 0; class = any; */
#define DNS_QTYPE_TSIG DNS_QTYPE_TSIG
	DNS_QTYPE_IXFR = 251,
#define DNS_QTYPE_IXFR DNS_QTYPE_IXFR
	DNS_QTYPE_AXFR = 252,
#define DNS_QTYPE_AXFR DNS_QTYPE_AXFR
	DNS_QTYPE_ANY = 255,
#define DNS_QTYPE_ANY DNS_QTYPE_ANY
	DNS_QTYPE_URI = 256,
#define DNS_QTYPE_URI DNS_QTYPE_URI
	DNS_QTYPE_TA = 32768,
#define DNS_QTYPE_TA DNS_QTYPE_TA
	DNS_QTYPE_DLV = 32769
#define DNS_QTYPE_DLV DNS_QTYPE_DLV
};

typedef enum QTYPE DNS_QTYPE;

enum QCLASS
{
	DNS_QCLASS_INET = 1,
#define DNS_QCLASS_INET DNS_QCLASS_INET
	DNS_QCLASS_CHAOS = 3,
#define DNS_QCLASS_CHAOS DNS_QCLASS_CHAOS
	DNS_QCLASS_HESIOD = 4,
#define DNS_QCLASS_HESIOD DNS_QCLASS_HESIOD
	DNS_QCLASS_NONE = 254,
#define DNS_QCLASS_NONE DNS_QCLASS_NONE
	DNS_QCLASS_ALL = 255
#define DNS_QCLASS_ALL DNS_QCLASS_ALL
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
} __attribute__((__packed__));

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
} __attribute__((__packed__));

typedef struct NAPTR_DATA NAPTR_DATA;

int encode_name(char *, char *, size_t *) __nonnull((1,2,3)) __wur;
int decode_name(char *, char *, char *, size_t) __nonnull((1,2,3)) __wur;
int convert_to_ptr(char *, char *, size_t *) __nonnull((1,2,3)) __wur;
int convert_to_ptr6(char *, char *, size_t *) __nonnull((1,2,3)) __wur;
int convert_nr_e164(char *, char *, size_t *) __nonnull((1,2,3)) __wur;
int get_name(char *, char *, buf_t *, size_t *) __nonnull((1,2,3,4)) __wur;
int get_records(cache_t *, u16, char *, char *, size_t, size_t *) __nonnull((1,3,4,6)) __wur;
int print_records(cache_t *, u16, char *, int) __nonnull((1,3)) __wur;

/* TODO Change rest of declarations */
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

/*wrappers*/
void *calloc_e(void *, size_t, size_t) __attribute__ ((alloc_size(2,3)));
void *malloc_e(void *, size_t) __attribute__ ((alloc_size(2)));
int socket_e(int, int, int, int);

/*a == 'all' */
ssize_t send_a(int, uc *, size_t, int) __THROW __nonnull ((2)) __wur;
ssize_t recv_a(int, uc *, size_t, int) __THROW __nonnull ((2)) __wur;
ssize_t sendto_a(int, uc *, size_t, int, struct sockaddr *, socklen_t) __THROW __nonnull ((2)) __wur;
ssize_t recvfrom_a(int, uc *, size_t, int, struct sockaddr *, socklen_t *) __THROW __nonnull ((2,5,6)) __wur;

#endif /* !defined ORION_H */
