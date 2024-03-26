#ifndef NETHER_H
#define NETHER_H

#define ENABLE_ARP    1
#define ENABLE_RINGBUFFER  1
#define ENABLE_TIMER   1
#define ENABLE_MULTHREAD   1
#define ENABLE_UDP_APP     1
#define ENABLE_TCP_APP     1
#define ENABLE_KNI_APP     1


#define MAX_FD_COUNT      1024
#define NUM_MBUFS (4096-1)
#define BURST_SIZE  32
#define MAX_PACKET_SIZE   2048
#define TIMER_RESOLUTION_CYCLES 120000000000ULL // 10ms * 1000 = 10s * 6

#define MAKE_IPV4_ADDR(a, b, c, d)  (a + (b << 8) + (c << 16) + (d << 24))


unsigned char fd_table[MAX_FD_COUNT];
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN];

#endif // NETHER_H
