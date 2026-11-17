#ifndef OSMEDIC_IO_LATENCY_H
#define OSMEDIC_IO_LATENCY_H

#define IO_LATENCY_SLOTS 32
#define IO_LATENCY_OPERATIONS 2

struct io_start {
	__u64 timestamp_ns;
	__u32 bytes;
	__u32 operation;
	__u32 had_error;
	__u32 padding;
};

/* per-CPU map 的用户态 value stride 必须是 8 字节的倍数。 */
struct io_histogram {
	__u64 slots[IO_LATENCY_SLOTS];
	__u64 bytes;
	__u64 latency_total_ns;
	__u64 errors;
};

/* floor(log2(us))，0/1 微秒合并到首桶，超范围落入最后一桶。 */
static __inline __attribute__((always_inline))
__u32 io_latency_slot(__u64 nanoseconds)
{
	__u64 us = nanoseconds / 1000;
	__u32 slot = 0;

	if (us >> 32) { us >>= 32; slot += 32; }
	if (us >> 16) { us >>= 16; slot += 16; }
	if (us >> 8) { us >>= 8; slot += 8; }
	if (us >> 4) { us >>= 4; slot += 4; }
	if (us >> 2) { us >>= 2; slot += 2; }
	if (us >> 1) { slot += 1; }
	return slot < IO_LATENCY_SLOTS ? slot : IO_LATENCY_SLOTS - 1;
}

/* Linux 6.6 在减少 rq->__data_len 之前触发 block_rq_complete。 */
static __inline __attribute__((always_inline))
int io_completion_is_final(__u32 completed, __u32 remaining, int has_bio)
{
	return !has_bio || completed >= remaining;
}

#endif
