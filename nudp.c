#include <stdio.h>
#include <arpa/inet.h>
#include <pthread.h>
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


struct localhost *lhost = NULL;

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

static void *get_hostinfo_fromfd(int sockfd)
{
    struct localhost *host;

    for (host = lhost; host != NULL; host = host->next) {
        if (sockfd == host->fd)
            return host;
    }

    return NULL;
}

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint16_t port, uint8_t proto)
{

    struct localhost *host;

    for (host = lhost; host != NULL; host = host->next) {

        if (dip == host->localip && port == host->localport && proto == host->protocol)
            return host;
    }

    return NULL;

}


static int nsocket(__attribute__((unused)) int domain, int type, __attribute__((unused)) int protocol)
{

    int fd = get_fd_frombitmap();

    if (type == SOCK_DGRAM) {

        struct localhost *host = rte_malloc("localhost", sizeof(struct localhost), 0);
        if (host == NULL)
            return -1;

        memset(host, 0, sizeof(struct localhost));
        host->fd = fd;
        host->protocol = IPPROTO_UDP;
        host->rcvbuf = rte_ring_create("rev buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (host->rcvbuf == NULL) {
            rte_free(host);
            return -1;
        }

        host->sndbuf = rte_ring_create("snd buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
        if (host->sndbuf == NULL) {
            rte_ring_free(host->rcvbuf);
            rte_free(host);
            return -1;
        }

        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
        rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));

        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
        rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));

        LL_ADD(host, lhost);

    } else if (type == SOCK_STREAM) {
//        struct ng_tcp_stream *stream = rte_malloc("ng_tcp_stream", sizeof(struct ng_tcp_stream), 0);
//        if (stream == NULL)
//            return -1;
//        memset(stream, 0, sizeof(struct ng_tcp_stream));

//        stream->fd = fd;
//        stream->protocol = IPPROTO_TCP;
//        stream->next = stream->prev = NULL;

//        stream->rcvbuf = rte_ring_create("tcp_recv_buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
//        if (stream->rcvbuf == NULL) {
//            rte_free(stream);
//            return -1;
//        }

//        stream->sndbuf = rte_ring_create("tcp_snd_buffer", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
//        if (stream->sndbuf == NULL) {
//            rte_ring_free(stream->rcvbuf);
//            rte_free(stream);
//            return -1;
//        }

//        pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
//        rte_memcpy(&stream->cond, &blank_cond, sizeof(pthread_cond_t));
//        pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
//        rte_memcpy(&stream->mutex, &blank_cond, sizeof(pthread_mutex_t));

//        struct ng_tcp_table *table = tcpInstance();
//        LL_ADD(stream, table->tcb_set);

    }

    return fd;
}

static int nbind(int sockfd, const struct sockaddr *addr,
                __attribute__((unused)) socklen_t addrlen)
{

    void *hostinfo = get_hostinfo_fromfd(sockfd);
    if (hostinfo == NULL) return -1;

    struct localhost *host = (struct localhost *) hostinfo;
    if (host->protocol == IPPROTO_UDP) {

        const struct sockaddr_in *laddr = (const struct sockaddr_in *)addr;
        host->localport = laddr->sin_port;
        rte_memcpy(&host->localip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
        rte_memcpy(host->localmac, gSrcMac, RTE_ETHER_ADDR_LEN);

    } else if (host->protocol == IPPROTO_TCP) {

    }

    return 0;
}

static ssize_t nrecvfrom(int sockfd, void *buf, size_t len, __attribute__((unused)) int flags,
                        struct sockaddr *src_addr, __attribute__((unused)) socklen_t *addrlen)
{

    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    struct offload *ol = NULL;
    unsigned char *ptr = NULL;

    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
    int nb = -1;
    pthread_mutex_lock(&host->mutex);
    while ((nb = rte_ring_mc_dequeue(host->rcvbuf, (void **)&ol)) < 0) {
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    pthread_mutex_unlock(&host->mutex);

    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr, &ol->sip, sizeof(uint32_t));

    if (len < ol->length) {

        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char *", ol->length-len, 0);
        rte_memcpy(ptr, ol->data+len, ol->length - len);

        ol->length -= len;
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->rcvbuf, ol);

        return len;
    } else {
        rte_memcpy(buf, ol->data, ol->length);

        uint16_t tmp_len = ol->length;
        rte_free(ol->data);
        rte_free(ol);

        return tmp_len;
    }
}

static ssize_t nsendto(int sockfd, const void *buf, size_t len, __attribute__((unused)) int flags,
                        const struct sockaddr *dest_addr, __attribute__((unused)) socklen_t addrlen)
{

    struct localhost *host = get_hostinfo_fromfd(sockfd);
    if (host == NULL) return -1;

    const struct sockaddr_in *daddr = (const struct sockaddr_in *)dest_addr;

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->localip;
    ol->sport = host->localport;
    ol->length = len;

    struct in_addr addr;
    addr.s_addr = ol->dip;
    printf("nsendto ---> src: %s:%d ,len:%ld\n", inet_ntoa(addr), ntohs(ol->dport), len);

    ol->data = rte_malloc("unsigned char *", len, 0);
    if (ol->data == NULL) {
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);
    rte_ring_mp_enqueue(host->sndbuf, ol);

    return len;
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

//        struct ng_tcp_stream *stream = (struct ng_tcp_stream *)hostinfo;

//        if (stream->status != NG_TCP_STATUS_LISTEN) {

//            struct ng_tcp_fragment *fragment = rte_malloc("bg_tcp_fragment", sizeof(struct ng_tcp_fragment), 0);
//            if (fragment == NULL) return -1;

//            printf("nclose --> enter last ack\n");
//            fragment->data = NULL;
//            fragment->length = 0;
//            fragment->sport = stream->dport;
//            fragment->dport = stream->sport;
//            fragment->seqnum = stream->snd_nxt;
//            fragment->acknum = stream->rcv_nxt;

//            fragment->tcp_flags = RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG;
//            fragment->windows = TCP_INITIAL_WINDOW;
//            fragment->hdrlen_off = 0x50;

//            rte_ring_mp_enqueue(stream->sndbuf, fragment);
//            stream->status = NG_TCP_STATUS_LAST_ACK;

//            set_fd_frombitmap(fd);
//        } else {  //nsocket

//            struct ng_tcp_table *table = tcpInstance();
//            LL_REMOVE(stream, table->tcb_set);

//            rte_free(stream);
//        }
    }

    return 0;
}

int udp_process(struct rte_mbuf *udpmbuf)
{

    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr = (struct rte_udp_hdr *)(iphdr + 1);
    //struct rte_udp_hdr *udphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_udp_hdr *, sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    struct in_addr addr,dst_addr;
    addr.s_addr = iphdr->src_addr;
//    printf("udp_process --> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));
//    dst_addr.s_addr = iphdr->dst_addr;
//    printf("udp_process --> dst: %s:%d \n", inet_ntoa(dst_addr), ntohs(udphdr->dst_port));

    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);
    if (host == NULL) {
        rte_pktmbuf_free(udpmbuf);
        return -3;
    }

    printf("udp_process --> src: %s:%d \n", inet_ntoa(addr), ntohs(udphdr->src_port));
    dst_addr.s_addr = iphdr->dst_addr;
    printf("udp_process --> dst: %s:%d \n", inet_ntoa(dst_addr), ntohs(udphdr->dst_port));

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if (ol == NULL) {

        rte_pktmbuf_free(udpmbuf);
        return -1;
    }

    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;

    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);

    ol->data = rte_malloc("unsigned char*", ol->length - sizeof(struct rte_udp_hdr), 0);
    if (ol->data == NULL) {

        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);

        return -2;
    }

    rte_memcpy(ol->data, (unsigned char *)(udphdr+1), ol->length - sizeof(struct rte_udp_hdr));

    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);

    return 0;
}

int ng_encode_udp_apppkt(uint8_t *msg, uint32_t sip, uint32_t dip, uint16_t sport,
                                uint16_t dport, uint8_t *srcmac, uint8_t *dstmac,
                                unsigned char *data, uint16_t total_len)
{

    //encode
    //1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0x00;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = sip;
    ip->dst_addr = dip;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 udphdr
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->dst_port = dport;
    udp->src_port = sport;
    u_int16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t *)(udp+1), data, udplen);
    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    return 0;
}

static struct rte_mbuf * ng_udp_pkt(struct rte_mempool *mbuf_pool, uint32_t sip, uint32_t dip,
    uint16_t sport, uint16_t dport, uint8_t *srcmac, uint8_t *dstmac, uint8_t *data, uint16_t length)
{

	// mempool --> mbuf

	const unsigned total_len = length + 42;

	struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
	if (!mbuf) {
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
	}
	mbuf->pkt_len = total_len;
	mbuf->data_len = total_len;

	uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

	ng_encode_udp_apppkt(pktdata, sip, dip, sport, dport, srcmac, dstmac,
		data, total_len);

	return mbuf;

}

int udp_out(struct rte_mempool *mbuf_pool)
{

    struct localhost *host;
    for (host = lhost; host != NULL; host = host->next) {

        struct offload *ol;
        int nb_snd = rte_ring_mc_dequeue(host->sndbuf, (void **)&ol);
        if (nb_snd < 0) continue;

        struct in_addr addr;
        addr.s_addr = ol->dip;
        printf("udp_out ---> src: %s:%d\n", inet_ntoa(addr), ntohs(ol->dport));

        uint8_t *dstmac = ng_get_dst_macaddr(ol->dip);
        if (dstmac == NULL) {

            struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, ol->sip, ol->dip);
            struct inout_ring *ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
            rte_ring_mp_enqueue(host->sndbuf, ol);
        } else {

            struct rte_mbuf *udpbuf = ng_udp_pkt(mbuf_pool, ol->sip, ol->dip, ol->sport, ol->dport,
                                                 host->localmac, dstmac, ol->data, ol->length);
            struct inout_ring * ring = ringInstance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
        }
    }

    return 0;
}

int udp_server_entry(__attribute__((unused)) void *arg)
{
    struct sockaddr_in localaddr, clientaddr;
    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if (connfd == -1) {
        printf("sockfd failed\n");
        return -1;
    }

    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(8889);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr("192.168.1.103");

    nbind(connfd, (struct sockaddr*)&localaddr, sizeof(localaddr));

    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    socklen_t addrlen = sizeof(clientaddr);

    while (1) {

        if (nrecvfrom(connfd, buffer, UDP_APP_RECV_BUFFER_SIZE, 0,
                    (struct sockaddr*)&clientaddr, &addrlen) < 0) {
            continue;
        } else {
            printf("recv from %s:%d, data:%s\n", inet_ntoa(clientaddr.sin_addr),
                    ntohs(clientaddr.sin_port), buffer);
            nsendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
        }
    }

    nclose(connfd);
}
