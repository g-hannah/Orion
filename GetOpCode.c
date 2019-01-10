#include "dns.h"

uc *
GetOpCode(unsigned short opcode)
{
	switch(opcode)
	  {
		case(0):
		return("standard");
		break;
		case(1):
		return("inverse");
		break;
		case(2):
		return("status");
		break;
		case(4):
		return("notify");
		break;
		case(5):
		return("update");
		break;
		default:
		return("unknown");
	  }
}
