#ifndef NTCP_H
#define NTCP_H





#define BUFFER_SIZE  1024
#define TCP_OPTION_LENGTH  10

#define TCP_MAX_SEQ		4294967295
#define TCP_INITIAL_WINDOW  14600


typedef enum _NG_TCP_STATUS {

    NG_TCP_STATUS_CLOSED = 0,
    NG_TCP_STATUS_LISTEN,
    NG_TCP_STATUS_SYN_RCVD,
    NG_TCP_STATUS_SYN_SENT,
    NG_TCP_STATUS_ESTABLISHED,

    NG_TCP_STATUS_FIN_WAIT_1,
    NG_TCP_STATUS_FIN_WAIT_2,
    NG_TCP_STATUS_CLOSING,
    NG_TCP_STATUS_TIME_WAIT,

    NG_TCP_STATUS_CLOSE_WAIT,
    NG_TCP_STATUS_LAST_ACK

}NG_TCP_STATUS;

struct ng_tcp_stream { //tcp control block

    int fd;

    uint32_t dip;
    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    uint16_t dport;

    uint8_t protocol;

    uint16_t sport;
    uint32_t sip;

    uint32_t snd_nxt; //seqnum
    uint32_t rcv_nxt; //acknum

    NG_TCP_STATUS status;

    struct rte_ring *sndbuf;
    struct rte_ring *rcvbuf;

    struct ng_tcp_stream *prev;
    struct ng_tcp_stream *next;

    pthread_cond_t cond;
    pthread_mutex_t mutex;
};

struct ng_tcp_table {

    int count;
    struct ng_tcp_stream *tcb_set;
};


struct ng_tcp_fragment {

    uint16_t sport;
    uint16_t dport;
    uint32_t seqnum;
    uint32_t acknum;
    uint8_t  hdrlen_off;
    uint8_t  tcp_flags;
    uint16_t windows;
    uint16_t cksum;
    uint16_t tcp_urp;

    int optlen;
    uint32_t option[TCP_OPTION_LENGTH];

    uint8_t *data;
    uint32_t length;
};

struct ng_tcp_table *tInst;



struct offload {

    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char *data;
    uint16_t length;

    NG_TCP_STATUS status;
};


int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint8_t *srcmac,
                        uint8_t *dstmac, struct ng_tcp_fragment *fragment);
struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
                            uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment);
int ng_tcp_out(struct rte_mempool *mbuf_pool);
int tcp_server_entry(__attribute__((unused)) void *arg);
int ng_tcp_process(struct rte_mbuf *tcpmbuf);
#endif // NTCP_H
