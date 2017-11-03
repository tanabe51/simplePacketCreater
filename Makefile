PROGRAM=sendPacket
OBJS=main.o ether.o checksum.o ip.o tcp.o icmp.o
SRCS=$(OBJS:%.o=%.c)
CFLAGS=-Wall -g
$(PROGRAM):$(OBJS)
						 $(CC) $(CFLAGS)  -o $(PROGRAM) $(OBJS) 
