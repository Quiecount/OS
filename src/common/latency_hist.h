#ifndef OSMEDIC_LATENCY_HIST_H
#define OSMEDIC_LATENCY_HIST_H

/* Nanoseconds; eight subdivisions per power of two, <=12.5% bucket width.
 * The final bucket is overflow and must not be presented as a finite bound. */
#define OSMEDIC_FINE_SLOTS 384
static __inline __attribute__((always_inline)) unsigned int latency_bucket(unsigned long long ns)
{
    unsigned long long v = ns;
    unsigned int e = 0;
    if (v < 8) return (unsigned int)v;
    if (v >> 32) { v >>= 32; e += 32; }
    if (v >> 16) { v >>= 16; e += 16; }
    if (v >> 8) { v >>= 8; e += 8; }
    if (v >> 4) { v >>= 4; e += 4; }
    if (v >> 2) { v >>= 2; e += 2; }
    if (v >> 1) e += 1;
    unsigned int slot = (e - 2) * 8 + ((ns >> (e - 3)) & 7);
    return slot < OSMEDIC_FINE_SLOTS ? slot : OSMEDIC_FINE_SLOTS - 1;
}

static __inline __attribute__((always_inline)) unsigned long long latency_upper_ns(unsigned int slot)
{
    if (slot < 8) return slot;
    unsigned int e = slot / 8 + 2;
    return ((9ULL + slot % 8) << (e - 3)) - 1;
}
#endif
