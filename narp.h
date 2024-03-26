#ifndef NARP_H
#define NARP_H


#define ARP_ENTRY_STATUS_DYNAMIC    0
#define ARP_ENTRY_STATUS_STATIC     1

struct arp_entry {
    uint32_t ip;
    uint8_t hwaddr[RTE_ETHER_ADDR_LEN];

    uint8_t type;

    struct arp_entry *next;
    struct arp_entry *prev;
};

struct  arp_table {
    struct arp_entry *entries;
    int count;

    pthread_spinlock_t  spinlock;
};


#define LL_ADD(item, list) do {   \
    item->prev = NULL;            \
    item->next = list;            \
    if (list != NULL) list->prev = item;  \
    list = item;  \
} while (0)

#define LL_REMOVE(item, list) do {          \
    if (item->prev != NULL) item->prev->next = item->next;    \
    if (item->next != NULL) item->next->prev = item->prev;    \
    if (list == item) list = item->next;  \
    item->prev = item->next = NULL;  \
} while (0)


uint8_t* ng_get_dst_macaddr(uint32_t dip);
int ng_arp_entry_insert(uint32_t ip, uint8_t *mac);
struct rte_mbuf *ng_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip);

#endif // NARP_H
