#ifndef NRING_H
#define NRING_H

#define RING_SIZE   1024

struct inout_ring {
    struct rte_ring *in;
    struct rte_ring *out;
};

struct inout_ring *rInst;


struct inout_ring *ringInstance(void);

#endif // NRING_H
