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

struct inout_ring *rInst = NULL;


struct inout_ring *ringInstance(void)
{
    if (rInst == NULL) {
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        memset(rInst, 0, sizeof(struct inout_ring));
    }

    return rInst;
}
