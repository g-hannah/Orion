#include "dns.h"

uc *
GetQClass(unsigned short qclass)
{
	switch(qclass)
	  {
		case(1):
		return("internet");
		break;
		case(QCLASS_CHAOS):
		return("chaos");
		break;
		case(QCLASS_HESIOD):
		return("hesiod");
		break;
		case(QCLASS_NONE):
		return("none");
		break;
		case(QCLASS_ALL):
		return("all");
		break;
		default:
		return("unknown");
	  }
}
