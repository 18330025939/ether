#ifndef NUDP_H
#define NUDP_H

#define DEFAULT_FD_NUM    3
#define UDP_APP_RECV_BUFFER_SIZE	128


struct localhost {
    int fd;

    uint32_t localip;
    uint8_t  localmac[RTE_ETHER_ADDR_LEN];
    uint16_t localport;

    uint8_t  protocol;

    struct  rte_ring *sndbuf;
    struct  rte_ring *rcvbuf;

    struct localhost *prev;
    struct localhost *next;

    pthread_cond_t cond;
    pthread_mutex_t  mutex;

};

struct localhost *lhost;

int udp_process(struct rte_mbuf *udpmbuf);
int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport,
                                uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
                                unsigned char *data, uint16_t total_len);
int udp_out(struct rte_mempool *mbuf_pool);
int udp_server_entry(__attribute__((unused)) void *arg);
#endif // NUDP_H
