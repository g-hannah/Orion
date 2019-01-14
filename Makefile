CC=gcc
FLAGS=-g
CFILES=main.c DoQuery.c DoTCP.c DoUDP.c DHCP_GetNS.c GetRecords.c GetAnswers.c ConvertName.c ConvertToPtr.c ConvertToPtr6.c ConvertNumberToE164.c HandleNAPTRrecord.c GetName.c GetOpCode.c GetQClass.c GetQType.c GetRCode.c PrintInfoDNS.c lib.c wrappers.c dns.h

orion: $(CFILES)
	$(CC) $(FLAGS) -o orion $(CFILES)
