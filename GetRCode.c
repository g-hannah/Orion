#include "dns.h"

uc *
GetRCode(unsigned short rcode)
{
	switch(rcode)
	  {
		case(0):
		return("\e[1;02m\e[1;32mno error\e[m");
		break;
		case(1):
		return("\e[3;31mformat error\e[m");
		break;
		case(2):
		return("\e[3;31mserver failure\e[m");
		break;
		case(3):
		return("\e[3;31mnon-existent domain\e[m");
		break;
		case(4):
		return("\e[3;31mnot implemented\e[m");
		break;
		case(5):
		return("\e[3;31mquery refused\e[m");
		break;
		case(6):
		return("\e[3;31mname exists but should not\e[m");
		break;
		case(7):
		return("\e[3;31mRRSet exists but should not\e[m");
		break;
		case(8):
		return("\e[3;31mRRSet does not exist but should\e[m");
		break;
		case(9):
		return("\e[3;31mserver not authorised for zone\e[m");
		break;
		case(10):
		return("\e[3;31mname not contained in zone\e[m");
		break;
		case(16):
		return("\e[3;31mbad SIG\e[m");
		break;
		case(17):
		return("\e[3;31mbad key\e[m");
		break;
		case(18):
		return("\e[3;31mbad time\e[m");
		break;
		default:
		return("\e[3;31munknown\e[m");
	  }
}
