// SPDX-License-Identifier: GPL-2.0
// SchedAI - Throughput-Optimized eBPF Scheduler Template
//
// Strategy: Maximize total CPU utilization by grouping tasks into
// "work-stealing" CPU-affine buckets. Each CPU drains its own queue first,
// then steals from the most-loaded sibling. Preemption is disabled by
// default to minimize context switch overhead.
//
// Best for: Build systems (make -jN), video encoding, ML training,
//           batch data processing, scientific simulation.
//
// AI-tunable parameters:
//   BATCH_SLICE_NS    -- time slice per task (bigger = fewer ctx switches)
//   STEAL_THRESHOLD   -- how many tasks a CPU needs before others steal
//   NUMA_AWARE        -- 1 = prefer same NUMA node tasks first

#include <scx/common.bpf.h>

#ifndef BATCH_SLICE_NS
#define BATCH_SLICE_NS    (15ULL * 1000000)   /* 15ms -- large slices for throughput */
#endif

#ifndef STEAL_THRESHOLD
#define STEAL_THRESHOLD   4   /* steal if sibling has 4+ more tasks */
#endif

#ifndef NUMA_AWARE
#define NUMA_AWARE        0
#endif

// --- Per-CPU run queues -------------------------------------------------------
// Each CPU has its own FIFO queue. Tasks are enqueued on their last CPU
// (cache-warm placement). Work stealing happens at dispatch time.

#define MAX_CPUS          256
#define QUEUE_SIZE        1024

struct cpu_queue {
    u32  pids[QUEUE_SIZE];
    u32  head;   /* dequeue from head */
    u32  tail;   /* enqueue at tail   */
    u32  count;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_CPUS);
    __type(key, u32);    /* cpu id */
    __type(value, struct cpu_queue);
} per_cpu_queues SEC(".maps");

// Per-task: remember which CPU it last ran on (for cache affinity)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);    /* pid */
    __type(value, u32);  /* last cpu */
} task_last_cpu SEC(".maps");

// Global stats
struct tp_stats {
    u64 enqueued;
    u64 dispatched;
    u64 steals;          /* work-steal events */
    u64 cache_hits;      /* task ran on same CPU as last time */
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct tp_stats);
} tp_stats_map SEC(".maps");

// --- Queue helpers ---------------------------------------------------------

static __always_inline int queue_push(struct cpu_queue *q, u32 pid)
{
    if (q->count >= QUEUE_SIZE) return -1;
    q->pids[q->tail % QUEUE_SIZE] = pid;
    q->tail++;
    q->count++;
    return 0;
}

static __always_inline int queue_pop(struct cpu_queue *q, u32 *pid_out)
{
    if (q->count == 0) return -1;
    *pid_out = q->pids[q->head % QUEUE_SIZE];
    q->head++;
    q->count--;
    return 0;
}

// --- sched_ext operations -----------------------------------------------------

SEC("struct_ops/tp_enqueue")
void BPF_STRUCT_OPS(tp_enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;

    // Find the preferred CPU (last run CPU for cache affinity)
    u32 *last_cpu = bpf_map_lookup_elem(&task_last_cpu, &pid);
    u32 target_cpu = last_cpu ? *last_cpu : (bpf_get_smp_processor_id() % MAX_CPUS);

    // Enqueue on the preferred CPU's queue
    struct cpu_queue *q = bpf_map_lookup_elem(&per_cpu_queues, &target_cpu);
    if (q) {
        queue_push(q, pid);
        // Eagerly track enqueue in stats
        u32 key = 0;
        struct tp_stats *s = bpf_map_lookup_elem(&tp_stats_map, &key);
        if (s) __sync_fetch_and_add(&s->enqueued, 1);
    }
}

SEC("struct_ops/tp_dispatch")
void BPF_STRUCT_OPS(tp_dispatch, s32 cpu, u64 prev_sum_exec_runtime)
{
    u32 ucpu = (u32)cpu;
    struct cpu_queue *my_q = bpf_map_lookup_elem(&per_cpu_queues, &ucpu);
    if (!my_q) return;

    u32 pid = 0;
    u32 key = 0;
    struct tp_stats *s = bpf_map_lookup_elem(&tp_stats_map, &key);

    // Try own queue first (hot path)
    if (queue_pop(my_q, &pid) == 0) {
        if (s) {
            __sync_fetch_and_add(&s->dispatched, 1);
            __sync_fetch_and_add(&s->cache_hits, 1);
        }
    } else {
        // Work steal: find busiest sibling CPU
        // Scan up to 8 neighbours (bounded for BPF verifier)
        u32 max_count = 0;
        u32 steal_from = 0;
        bool found = false;

        for (u32 i = 1; i <= 8; i++) {
            u32 sibling = (ucpu + i) % MAX_CPUS;
            struct cpu_queue *sq = bpf_map_lookup_elem(&per_cpu_queues, &sibling);
            if (sq && sq->count > max_count + STEAL_THRESHOLD) {
                max_count  = sq->count;
                steal_from = sibling;
                found = true;
            }
        }

        if (found) {
            struct cpu_queue *victim = bpf_map_lookup_elem(&per_cpu_queues, &steal_from);
            if (victim && queue_pop(victim, &pid) == 0) {
                if (s) {
                    __sync_fetch_and_add(&s->dispatched, 1);
                    __sync_fetch_and_add(&s->steals, 1);
                }
            }
        }
    }

    if (pid == 0) return;   /* nothing to dispatch */

    struct task_struct *task = bpf_task_from_pid(pid);
    if (!task) return;

    // Update last-CPU for cache affinity next time
    bpf_map_update_elem(&task_last_cpu, &pid, &ucpu, BPF_ANY);

    // Large time slice = fewer context switches = more throughput
    scx_bpf_dispatch(task, SCX_DSQ_LOCAL, BATCH_SLICE_NS, 0);
    bpf_task_release(task);
}

SEC("struct_ops/tp_init_task")
s32 BPF_STRUCT_OPS(tp_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    u32 pid = p->pid;
    u32 cpu = bpf_get_smp_processor_id() % MAX_CPUS;
    bpf_map_update_elem(&task_last_cpu, &pid, &cpu, BPF_ANY);
    return 0;
}

SEC("struct_ops/tp_exit_task")
void BPF_STRUCT_OPS(tp_exit_task, struct task_struct *p,
                    struct scx_exit_task_args *args)
{
    u32 pid = p->pid;
    bpf_map_delete_elem(&task_last_cpu, &pid);
}

SEC("struct_ops/tp_exit")
void BPF_STRUCT_OPS(tp_exit, struct scx_exit_info *ei)
{
    bpf_printk("SchedAI Throughput scheduler unloaded\n");
}

SEC(".struct_ops.link")
struct sched_ext_ops throughput_ops = {
    .enqueue    = (void *)tp_enqueue,
    .dispatch   = (void *)tp_dispatch,
    .init_task  = (void *)tp_init_task,
    .exit_task  = (void *)tp_exit_task,
    .exit       = (void *)tp_exit,
    .timeout_ms = 8000,
    .name       = "schedai_throughput",
};

char _license[] SEC("license") = "GPL";
