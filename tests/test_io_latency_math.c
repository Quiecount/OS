#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/types.h>
#include "io_latency.h"

int main(void)
{
	/* 以对数桶的数学边界验证 0/1us 合并及所有有限桶。 */
	assert(io_latency_slot(0) == 0);
	assert(io_latency_slot(999) == 0);
	assert(io_latency_slot(1999) == 0);
	for (__u32 slot = 1; slot < IO_LATENCY_SLOTS; slot++) {
		__u64 lower_ns = (1ULL << slot) * 1000;

		assert(io_latency_slot(lower_ns - 1) == slot - 1);
		assert(io_latency_slot(lower_ns) == slot);
	}
	assert(io_latency_slot(UINT64_MAX) == IO_LATENCY_SLOTS - 1);
	/* 部分完成保留计时；最后一段、零剩余或无 bio 才结束。 */
	assert(!io_completion_is_final(4096, 8192, 1));
	assert(!io_completion_is_final(0, 8192, 1));
	assert(io_completion_is_final(4096, 4096, 1));
	assert(io_completion_is_final(8192, 4096, 1));
	assert(io_completion_is_final(0, 0, 1));
	assert(io_completion_is_final(0, 8192, 0));
	puts("PASS: histogram boundaries and partial-completion decisions");
	return 0;
}
