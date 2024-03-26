#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>

#include <rte_ether.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <rte_malloc.h>
#include <rte_timer.h>
#include <rte_log.h>
#include <rte_kni.h>
#include "nether.h"
#include "narp.h"
#include "ntcp.h"
#include "nudp.h"
#include "nring.h"

struct ng_tcp_table *tInst = NULL;
// uint8_t gDefaultArpMac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};


static int get_fd_frombitmap(void)
{
    int fd = DEFAULT_FD_NUM;
    for (; fd < MAX_FD_COUNT; fd ++) {
        if ((fd_table[fd/8] & (0x01 << (fd % 8))) == 0 ) {
            fd_table[fd/8] |= (0x01 << (fd % 8));
            return fd;
        }
    }

    return -1;
}

static int set_fd_frombitmap(int fd)
{
    if (fd >= MAX_FD_COUNT) return -1;
    fd_table[fd/8] &= ~(0x01 << (fd % 8));

    return 0;
}
static struct ng_tcp_table *tcpInstance(void)
{
    if (tInst == NULL) {
        tInst = rte_malloc("ng_tcp_table", sizeof(struct ng_tcp_table), 0);
        memset(tInst, 0, sizeof(struct ng_tcp_table));
    }

    return tInst;
}
static struct ng_tcp_stream *get_accept_tcb(uint16_t dport)
{

    struct ng_tcp_stream *apt;
    struct ng_tcp_table *table = tcpInstance();
    for (apt = table->tcb_set; apt != NULL; apt = apt->next) {
        if (dport == apt->dport && apt->fd == -1)
            return apt;
    }

    return NULL;
}


static void *get_hostinfo_fromfd(int sockfd)
{
#if ENABLE_TCP_APP

    struct ng_tcp_stream *stream = NULL;
    struct ng_tcp_table *table = tcpInstance();
    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {
        if (stream->fd == sockfd)
            return stream;
    }
#endif
    return NULL;
}
static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol)
{

    int fd = get_fd_frombitmap();

    if (type == SOCK_DGRAM) {

//        struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
//        if (host == NULL)
//            return -1;

//        memset(host, 0, sizeof(struct localhost));
//        host->fd = fd;
//        host->protocol = IPPROTO_UDP;
//        host->rcvbuf = rte_ring_create("rev buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
//        if (host->rcvbuf == NULL) {
//            rte_free(host);
//            return -1;
//        }

//        host->sndbuf = rte_ring_create("snd buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
//        if (host->sndbuf == NULL) {
//            rte_free(host);
//            return -1;
//        }

//        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
//        rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

//        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
//        rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

//        LL_ADD(host, lhost);

    } else if (type == SOCK_STREAM) {
         struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
        if (stream == NULL)
            return -1;
        memset(stream, 0, sizeof(struct ng_tcp_stream));

        stream->fd = fd;
        stream->protocol = IPPROTO_TCP;
        stream->next = stream->prev = NULL;

        stream->rcvbuf = rte_ring_create("tcp_recv_buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (stream->rcvbuf == NULL) {
            rte_free(stream);
            return -1;
        }

        stream->sndbuf = rte_ring_create("tcp_snd_buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (stream->sndbuf == NULL) {
            rte_ring_free(stream->rcvbuf);
            rte_free(stream);
            return -1;
        }

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));
        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        struct ng_tcp_table *table = tcpInstance();
        LL_ADD(stream, table->tcb_set);

    }

    return fd;
}
static int nlisten(int sockfd, __attribute__((unused)) int backlog)
{

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream*)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {
        stream->status = NG_TCP_STATUS_LISTEN;
    }

    return 0;
}

static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused)) socklen_t addrlen)
{

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct localhost *host = (struct localhost *) hostinfo;
    if (host->protocol == IPPROTO_UDP) {

//        const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
//        host->localport = laddr->sin_port;
//        rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
//        rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    } else if (host->protocol == IPPROTO_TCP) {

        struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;

        const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
        stream->dport = laddr->sin_port;
        rte_memcpy(&stream->dip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

        stream->status = NG_TCP_STATUS_CLOSED;
    }

    return 0;
}

static int naccept(int sockfd, struct sockaddr_in *addr, __attribute__((unused)) socklen_t *addr_len)
{

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct ng_tcp_stream *apt = NULL;

        pthread_mutex_lock(&stream->mutex);
        while ((apt = get_accept_tcb(stream->dport)) == NULL) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }
        pthread_mutex_unlock(&stream->mutex);

        apt->fd = get_fd_frombitmap();

        struct sockaddr_in *saddr = (struct sockaddr_in *)addr;
        saddr->sin_port = apt->sport;
        rte_memcpy(&saddr->sin_addr.s_addr, &apt->sip, sizeof(uint32_t));

        return apt->fd;
    }

    return -1;
}

static ssize_t nrecv(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags)
{

    ssize_t length = 0;

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct ng_tcp_fragment *fragment = NULL;
        int nb_rcv = 0;

        printf("rte_ring_mc_dequeue before\n");
        pthread_mutex_lock(&stream->mutex);
        while ((nb_rcv = rte_ring_mc_dequeue(stream->rcvbuf, (void **)&fragment)) < 0) {
            pthread_cond_wait(&stream->cond, &stream->mutex);
        }

        pthread_mutex_unlock(&stream->mutex);
        printf("rte_ring_mc_dequeue after\n");

        if (fragment->length > len) {

            rte_memcpy(&buf, fragment->data, len);
            uint32_t i = 0;
            for (i = 0; i < fragment->length - len; i++) {
                fragment->data[i] = fragment->data[len+i];
            }

            fragment->length = fragment->length - len;
            length = fragment->length;

            rte_ring_mp_enqueue(stream->rcvbuf, fragment);
        } else if (fragment->length == 0) {

            rte_free(fragment);
            return 0;
        } else {

            rte_memcpy(buf, fragment->data, fragment->length);
            length = fragment->length;

            rte_free(fragment->data);
            fragment->data = NULL;

            rte_free(fragment);
        }
    }

    return length;
}

static ssize_t nsend(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags)
{

    ssize_t length = 0;

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;
    if (stream->protocol == IPPROTO_TCP) {

        struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
        if (fragment == NULL)
            return -2;

        memset(fragment, 0, sizeof(struct ng_tcp_fragment));

        fragment->dport = stream->sport;
        fragment->sport = stream->dport;

        fragment->acknum = stream->rcv_nxt;
        fragment->seqnum = stream->snd_nxt;

        fragment->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        fragment->windows = TCP_INITIAL_WINDOW;
        fragment->hdrlen_off = 0x50;

        fragment->data = rte_malloc("unsigned char *", len+1, 0);
        if (fragment->data == NULL) {
            rte_free(fragment);
            return -1;
        }
        memset(fragment->data , 0, len+1);

        rte_memcpy(fragment->data, buf, len);
        fragment->length = len;
        length = fragment->length;

        rte_ring_mp_enqueue(stream->sndbuf, fragment);
    }

    return length;
}
static int nclose(int fd)
{

    void *hostinfo = get_hostinfo_fromfd(fd);
    if (hostinfo == NULL) return -1;

    struct localhost *host = (struct localhost *)hostinfo;
    if (host->protocol == IPPROTO_UDP) {

        LL_REMOVE(host, lhost);

        if (host->rcvbuf)
            rte_ring_free(host->rcvbuf);
        if (host->sndbuf)
            rte_ring_free(host->sndbuf);

        rte_free(host);
        set_fd_frombitmap(fd);

    } else if (host->protocol == IPPROTO_TCP) {

        struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;

        if (stream->status != NG_TCP_STATUS_LISTEN) {

            struct ng_tcp_fragment *fragment = rte_malloc("bg_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
            if (fragment == NULL) return -1;

            printf("nclose --> enter last ack\n");
            fragment->data = NULL;
            fragment->length = 0;
            fragment->sport = stream->dport;
            fragment->dport = stream->sport;
            fragment->seqnum = stream->snd_nxt;
            fragment->acknum = stream->rcv_nxt;

            fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
            fragment->windows = TCP_INITIAL_WINDOW;
            fragment->hdrlen_off = 0x50;

            rte_ring_mp_enqueue(stream->sndbuf, fragment);
            stream->status = NG_TCP_STATUS_LAST_ACK;

            set_fd_frombitmap(fd);
        } else {  //nsocket

            struct ng_tcp_table *table = tcpInstance();
            LL_REMOVE(stream, table->tcb_set);

            rte_free(stream);
        }
    }

    return 0;
}

int ng_encode_tcp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip,
                                uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment)
{

    //encode
    const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
            sizeof(struct rte_tcp_hdr) + fragment->optlen * sizeof(uint32_t);

    //1 ether
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = sip;
    ip->dst_addr = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 tcphdr
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    tcp->src_port = fragment->sport;
    tcp->dst_port = fragment->dport;
    tcp->sent_seq = htonl(fragment->seqnum);
    tcp->recv_ack = htonl(fragment->acknum);

    tcp->data_off = fragment->hdrlen_off;
    tcp->rx_win = fragment->windows;
    tcp->tcp_urp = fragment->tcp_urp;
    tcp->tcp_flags = fragment->tcp_flags;

    if (fragment->data != NULL) {

        uint8_t *payload = (uint8_t *)(tcp + 1) + fragment->optlen * sizeof(uint32_t);
        rte_memcpy(payload, fragment->data, fragment->length);
    }
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);

    return 0;
}


struct rte_mbuf * ng_tcp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
                                    uint8_t *srcmac, uint8_t *dstmac, struct ng_tcp_fragment *fragment)
{
    const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) +
            sizeof(struct rte_tcp_hdr) + fragment->optlen * sizeof(uint32_t);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {

        rte_exit(EXIT_FAILURE, "ng_tcp_pkt rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);
    ng_encode_tcp_apppkt(pktdata, sip, dip, srcmac, dstmac, fragment);

    return mbuf;
}

int ng_tcp_out(struct rte_mempool *mbuf_pool)
{

    struct ng_tcp_table *table = tcpInstance();
    struct ng_tcp_stream *stream;
    for (stream = table->tcb_set; stream != NULL; stream = stream->next) {

        if (stream->sndbuf == NULL) continue;

        struct ng_tcp_fragment *fragment = NULL;
        int ng_snd = rte_ring_mc_dequeue(stream->sndbuf, (void **)&fragment);
        if (ng_snd < 0) continue;

        uint8_t *dstmac = ng_get_dst_macaddr(stream->sip);
        if (dstmac == NULL) {

            struct rte_mbuf * arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, stream->dip, stream->sip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(stream->sndbuf, fragment);

        } else {

            struct rte_mbuf *tcpbuf = ng_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);

            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&tcpbuf, 1, NULL);

            if (fragment->data != NULL)
                rte_free(fragment->data);

            rte_free(fragment);
        }

    }

    return 0;
}

static struct ng_tcp_stream * ng_tcp_stream_search(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{

    struct ng_tcp_table *table = tcpInstance();
    struct ng_tcp_stream *iter;

    for (iter = table->tcb_set; iter != NULL; iter = iter->next) { //establisten

        if (iter->sip == sip && iter->dip == dip &&
            iter->sport ==  sport && iter->dport == dport) {
            return iter;
        }
    }

    for (iter = table->tcb_set; iter != NULL; iter = iter->next) { //listen
        if (iter->dport == dport && iter->status == NG_TCP_STATUS_LISTEN) {
            return iter;
        }
    }

    return NULL;
}

static struct ng_tcp_stream * ng_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport, uint16_t dport)
{

    //tcp --> status
    struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
    if (stream == NULL) return NULL;

    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->protocol = IPPROTO_TCP;
    stream->fd = -1;

    stream->status = NG_TCP_STATUS_LISTEN;
    printf("ng_tcp_stream_create\n");

    stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
    stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);

    uint32_t next_seed = time(NULL);
    stream->snd_nxt = rand_r(&next_seed) % TCP_MAX_SEQ;
    rte_memcpy(stream->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));

    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&stream->mutex, &blank_mutex, sizeof(pthread_mutex_t));

    return stream;

}

static  int ng_tcp_handle_listen(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, struct rte_ipv4_hdr *iphdr)
{

    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {
        //stream --> listenfd
        if (stream->status == NG_TCP_STATUS_LISTEN) {

            struct ng_tcp_table *table = tcpInstance();
            struct ng_tcp_stream *syn = ng_tcp_stream_create(iphdr->src_addr, iphdr->dst_addr, tcphdr->src_port, tcphdr->dst_port);
            LL_ADD(syn, table->tcb_set);

            struct ng_tcp_fragment *fragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
            if (fragment == NULL) return -1;
            memset(fragment, 0, sizeof(struct ng_tcp_fragment));

            fragment->sport = tcphdr->dst_port;
            fragment->dport = tcphdr->src_port;

            struct in_addr addr;
            addr.s_addr = syn->sip;
            printf("tcp --> src: %s:%d\n", inet_ntoa(addr), ntohs(tcphdr->src_port));
            addr.s_addr = syn->dip;
            printf("tcp --> dst: %s:%d\n", inet_ntoa(addr), ntohs(tcphdr->dst_port));

            fragment->seqnum = syn->snd_nxt;
            fragment->acknum = ntohl(tcphdr->sent_seq) + 1;
            syn->rcv_nxt = fragment->acknum;

            fragment->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
            fragment->windows = TCP_INITIAL_WINDOW;
            fragment->hdrlen_off = 0x50;

            fragment->data = NULL;
            fragment->length = 0;

            rte_ring_mp_enqueue(syn->sndbuf, fragment);

            syn->status = NG_TCP_STATUS_SYN_RCVD;

        }

    }

    return 0;
}

static int ng_tcp_enqueue_recvbuffer(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, int tcplen)
{

    // recv buffer
    struct ng_tcp_fragment *rfragment = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if (rfragment == NULL) return -1;
    memset(rfragment, 0, sizeof(struct ng_tcp_fragment));

    rfragment->dport = ntohs(tcphdr->dst_port);
    rfragment->sport = ntohs(tcphdr->src_port);

    uint8_t hdrlen = tcphdr->data_off >> 4;
    int payloadlen = tcplen - hdrlen * 4;
    if (payloadlen > 0) {

        uint8_t * payload = (uint8_t *)tcphdr + hdrlen * 4;
        rfragment->data = rte_malloc("unsigned char *", payloadlen + 1, 0);
        if (rfragment->data == NULL) {
            rte_free(rfragment);
            return -1;

        }
        memset(rfragment->data, 0, payloadlen + 1);
        rte_memcpy(rfragment->data, payload, payloadlen);
        rfragment->length = payloadlen;
    } else if (payloadlen == 0) {
        rfragment->length = 0;
        rfragment->data = NULL;
    }

    rte_ring_mp_enqueue(stream->rcvbuf, rfragment);

    pthread_mutex_lock(&stream->mutex);
    pthread_cond_signal(&stream->cond);
    pthread_mutex_unlock(&stream->mutex);

    return 0;
}

static int ng_tcp_handle_syn_rcvd(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {

        if (stream->status == NG_TCP_STATUS_SYN_RCVD) {

            uint32_t acksum = ntohl(tcphdr->recv_ack);
            if (acksum == stream->snd_nxt + 1) {

            }

            stream->status = NG_TCP_STATUS_ESTABLISHED;

            //accept
            struct ng_tcp_stream *listener = ng_tcp_stream_search(0, 0, 0, stream->dport);
            if (stream == NULL)
                rte_exit(EXIT_FAILURE, "ng_tcp_stream_search failed\n");

            pthread_mutex_lock(&listener->mutex);
            pthread_cond_signal(&listener->cond);
            pthread_mutex_unlock(&listener->mutex);
        }
    }

    return 0;
}

static int ng_tcp_send_ackpkt(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{

    struct ng_tcp_fragment *ackfrag = rte_malloc("ng_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
    if (ackfrag == NULL) return -1;
    memset(ackfrag, 0, sizeof(struct ng_tcp_fragment));

    ackfrag->dport = tcphdr->src_port;
    ackfrag->sport = tcphdr->dst_port;

    //remote
    printf("ng_tcp_send_ackpkt: %d, %d\n", stream->rcv_nxt, ntohs(tcphdr->sent_seq));
    ackfrag->acknum = stream->rcv_nxt;
    ackfrag->seqnum = stream->snd_nxt;

    ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
    ackfrag->windows = TCP_INITIAL_WINDOW;
    ackfrag->hdrlen_off = 0x50;
    ackfrag->data = NULL;
    ackfrag->length = 0;

    rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

    return 0;
}

static int ng_tcp_handle_established(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr, uint16_t tcplen)
{

    if (tcphdr->tcp_flags & RTE_TCP_SYN_FLAG) {

    }

    if (tcphdr->tcp_flags & RTE_TCP_PSH_FLAG) {

        ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcplen);

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen * 4;

        stream->rcv_nxt = stream->rcv_nxt + payloadlen;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        ng_tcp_send_ackpkt(stream, tcphdr);
    }

    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {


    }

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

        stream->status = NG_TCP_STATUS_CLOSE_WAIT;

        ng_tcp_enqueue_recvbuffer(stream, tcphdr, tcphdr->data_off >> 4);

        stream->rcv_nxt = stream->rcv_nxt + 1;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);

        ng_tcp_send_ackpkt(stream, tcphdr);
    }

    return 0;
}

static int ng_tcp_handle_close_wait(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{

    if (tcphdr->tcp_flags & RTE_TCP_FIN_FLAG) {

        if (stream->status == NG_TCP_STATUS_CLOSE_WAIT) {

        }
    }

    return 0;
}

static int ng_tcp_handle_last_ack(struct ng_tcp_stream *stream, struct rte_tcp_hdr *tcphdr)
{
    if (tcphdr->tcp_flags & RTE_TCP_ACK_FLAG) {
        if (stream->status == NG_TCP_STATUS_LAST_ACK) {

            stream->status = NG_TCP_STATUS_CLOSED;
            printf("ng_tcp_handle_last_ack\n");
            struct ng_tcp_table *table = tcpInstance();
            LL_REMOVE(stream, table->tcb_set);

            rte_ring_free(stream->sndbuf);
            rte_ring_free(stream->rcvbuf);

            rte_free(stream);
        }
    }

    return 0;
}

int ng_tcp_process(struct rte_mbuf *tcpmbuf)
{
    int tcplen = 0;
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *,
                                                         sizeof(struct rte_ether_hdr));
    //struct rte_tcp_hdr *tcphdr = (struct rte_tcp_hdr *)(iphdr + 1);
    struct rte_tcp_hdr *tcphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_tcp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));

//    struct in_addr src_addr, dst_addr;
//    src_addr.s_addr = iphdr->src_addr;
//    dst_addr.s_addr = iphdr->dst_addr;
//    printf("tcp_process --> src: %s:%d \n", inet_ntoa(src_addr), ntohs(tcphdr->src_port));
//    printf("tcp_process --> dst: %s:%d \n", inet_ntoa(dst_addr), ntohs(tcphdr->dst_port));


    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
//    printf("tcpcksum  cksum: %d:%d \n", tcpcksum, cksum);
#if 1
    if (cksum != tcpcksum) {
        printf("cksum failed\n");
        rte_pktmbuf_free(tcpmbuf);
        return -1;
    }
#endif
    struct ng_tcp_stream *stream = ng_tcp_stream_search(iphdr->src_addr, iphdr->dst_addr,
                                                        tcphdr->src_port, tcphdr->dst_port);
    if (stream == NULL ) {
        //printf("stream lookup failed\n");
        rte_pktmbuf_free(tcpmbuf);
        return -2;
    }

    switch (stream->status) {

        case NG_TCP_STATUS_CLOSED: //client
        break;
        case NG_TCP_STATUS_LISTEN: //server
            ng_tcp_handle_listen(stream, tcphdr, iphdr);
        break;
        case NG_TCP_STATUS_SYN_RCVD: //server
            ng_tcp_handle_syn_rcvd(stream, tcphdr);
        break;
        case NG_TCP_STATUS_SYN_SENT: //client
        break;
        case NG_TCP_STATUS_ESTABLISHED: //server | client
            tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);
            ng_tcp_handle_established(stream, tcphdr, tcplen);
        break;
        case NG_TCP_STATUS_FIN_WAIT_1: // ~client
        break;
        case NG_TCP_STATUS_FIN_WAIT_2: // ~client
        break;
        case NG_TCP_STATUS_CLOSING: // ~client
        break;
        case NG_TCP_STATUS_TIME_WAIT: // ~client

        break;
        case NG_TCP_STATUS_CLOSE_WAIT: // ~sever
            ng_tcp_handle_close_wait(stream, tcphdr);
        break;
        case NG_TCP_STATUS_LAST_ACK: // ~server
            ng_tcp_handle_last_ack(stream, tcphdr);
        break;
    }

    rte_pktmbuf_free(tcpmbuf);

    return 0;
}

int tcp_server_entry(__attribute__((unused)) void *arg)
{

    struct sockaddr_in servaddr;
    int listenfd = nsocket(AF_INET, SOCK_STREAM, 0);
    if (listenfd == -1)
        return -1;

    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(9999);
    nbind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    nlisten(listenfd, 10);

    while (1) {

        struct sockaddr_in clientaddr;
        socklen_t len = sizeof (clientaddr);
        int connfd = naccept(listenfd, (struct sockaddr_in *)&clientaddr, &len);

        char buff[BUFFER_SIZE] = {0};
        while (1) {

            int n = nrecv(connfd, buff, BUFFER_SIZE, 0);
            if (n > 0) {
                printf("recv: %s\n", buff);
                nsend(connfd, buff, n, 0);
            } else if (n == 0) {
                nclose(connfd);
                break;
            } else { //nonblock

            }
        }
    }

    nclose(listenfd);

}
