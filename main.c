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


#if ENABLE_KNI_APP
struct rte_kni *global_kni = NULL;
#endif


static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 1, 103);
static int gDpdkPortId = 0;
uint8_t fd_table[MAX_FD_COUNT] = {0};
uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};



#if ENABLE_KNI_APP

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN }
};

static void ng_init_port(struct rte_mempool *mbuf_pool)
{

    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0)
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;
    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);

    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 1024, rte_eth_dev_socket_id(gDpdkPortId),
                                NULL, mbuf_pool) < 0)
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");

    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;
    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 1024,
                                rte_eth_dev_socket_id(gDpdkPortId), (const struct rte_eth_txconf *)&txq_conf) < 0)
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");

    if (rte_eth_dev_start(gDpdkPortId) < 0)
        rte_exit(EXIT_FAILURE, "Could not start\n");

    rte_eth_promiscuous_enable(gDpdkPortId);
}

static void print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s: %s\n",name, buf);
}

static int ng_config_network_if(uint16_t port_id, uint8_t if_up)
{

    if (!rte_eth_dev_is_valid_port(port_id))
        return -EINVAL;
    int ret = 0;
    if (if_up) {
        rte_eth_dev_stop(port_id);
        ret = rte_eth_dev_start(port_id);
    } else
        rte_eth_dev_stop(port_id);

    if (ret < 0)
        printf("Failed to start port: %d\n", port_id);

    return 0;

}
static struct rte_kni *ng_alloc_kni(struct rte_mempool *mbuf_pool)
{

    struct rte_kni *kni_hanlder = NULL;
    struct rte_kni_conf conf;
    memset(&conf, 0, sizeof(conf));

    snprintf(conf.name, RTE_KNI_NAMESIZE, "vEth%u", gDpdkPortId);
    conf.group_id = gDpdkPortId;
    conf.mbuf_size = MAX_PACKET_SIZE;
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr*)conf.mac_addr);
    rte_eth_dev_get_mtu(gDpdkPortId, &conf.mtu);

    print_ethaddr("ng_alloc_kni", (struct rte_ether_addr *)conf.mac_addr);

    struct rte_kni_ops ops;
    memset(&ops, 0, sizeof(ops));

    ops.port_id = gDpdkPortId;
    ops.config_network_if = ng_config_network_if;

    kni_hanlder = rte_kni_alloc(mbuf_pool, &conf, &ops);
    if (!kni_hanlder)
        rte_exit(EXIT_FAILURE, "Failed to create kni for port: %d\n", gDpdkPortId);

    return kni_hanlder;
}
#endif


#if ENABLE_TIMER

static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim, void *arg)
{
    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    int i = 0;
    for (i = 1; i <= 254; i ++) {
        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));

        struct rte_mbuf *arpbuf = NULL;
        uint8_t *dstmac = ng_get_dst_macaddr(dstip);
        if (dstmac == NULL) {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);
        } else {
            arpbuf = ng_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
        }

        rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
    }
}
#endif

#if ENABLE_MULTHREAD
static int pkt_process(__attribute__((unused)) void *arg)
{

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring *ring = ringInstance();

    while (1) {

        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_ring_dequeue_burst(ring->in, (void *)mbufs, BURST_SIZE, NULL);
        unsigned i = 0;

        for (i = 0; i < num_recvd; i++) {

            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr *);
            if (ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {

                struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));

                ng_arp_entry_insert(iphdr->src_addr, ehdr->s_addr.addr_bytes);

                if (iphdr->next_proto_id == IPPROTO_UDP) {

                    udp_process(mbufs[i]);
                } else if (iphdr->next_proto_id == IPPROTO_TCP) {
                    //printf("iphdr->next_proto_id: IPPROTO_TCP\n");
                    ng_tcp_process(mbufs[i]);
                } else {

                    rte_kni_tx_burst(global_kni, mbufs, num_recvd);
                    //printf("tcp/udp --> rte_kni_handle_request\n");
                }
            } else {

                rte_kni_tx_burst(global_kni, mbufs, num_recvd);
                //printf("ip --> rte_free_kni_handle_request\n");
            }
        }

        rte_kni_handle_request(global_kni);

#if ENABLE_UDP_APP
        udp_out(mbuf_pool);
#endif

#if ENABLE_TCP_APP
        ng_tcp_out(mbuf_pool);
#endif
    }

    return 0;

}
#endif





int main (int argc, char **argv)
{

    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_MBUFS,
                                    0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

#if ENABLE_KNI_APP

    if (-1 == rte_kni_init(gDpdkPortId))
        rte_exit(EXIT_FAILURE, "kni init failed\n");

    ng_init_port(mbuf_pool);
    //kni_alloc
    global_kni = ng_alloc_kni(mbuf_pool);
#endif
    printf("gDpdkPortId: %d\n", gDpdkPortId);
    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
    print_ethaddr("gSrcMac", (struct rte_ether_addr *)gSrcMac);
    //printf("gSrcMac : %s\n", gSrcMac);
#if ENABLE_TIMER
    rte_timer_subsystem_init();

    struct rte_timer arp_timer;
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();
    rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);
#endif


#if ENABLE_RINGBUFFER

    struct inout_ring *ring = ringInstance();
    if (ring == NULL)
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");

    if (ring->in == NULL) {
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);

    }
    if (ring->out == NULL) {
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_SC_DEQ);
    }
#endif

#if ENABLE_MULTHREAD
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);
#endif

#if ENABLE_UDP_APP
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, mbuf_pool, lcore_id);
#endif

#if ENABLE_TCP_APP
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(tcp_server_entry, mbuf_pool, lcore_id);
#endif

    while (1) {

        //rx
        struct rte_mbuf *rx[BURST_SIZE];
        uint16_t num_recvd = rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving form eth\n");

        } else if (num_recvd > 0) {
            rte_ring_sp_enqueue_burst(ring->in, (void**)rx, num_recvd, NULL);

        }

        //tx
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void**)tx, BURST_SIZE, NULL);
        if (nb_tx > 0) {
            rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);

            unsigned i = 0;
            for (i = 0; i < nb_tx; i++) {
                rte_pktmbuf_free(tx[i]);
            }
        }


#if ENABLE_TIMER

        static uint64_t prev_tsc = 0, cur_tsc;
        uint64_t  diff_tsc;

        cur_tsc = rte_rdtsc();
        diff_tsc = cur_tsc - prev_tsc;
        if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
            rte_timer_manage();
            prev_tsc = cur_tsc;
        }

#endif

    }

    return 0;
}
