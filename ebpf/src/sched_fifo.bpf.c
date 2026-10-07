// SPDX-License-Identifier: GPL-2.0
// SchedAI - FIFO Template eBPF Scheduler
// Uses sched_ext (BPF Extensible Scheduler Class)
//
// How it works:
//   Tasks are placed in a simple FIFO queue. The scheduler picks the oldest
//   waiting task first. Preemption is disabled -- each task runs until it
//   voluntarily yields or sleeps.
//
// AI-tunable parameters (injected at compile-time via -D flags):
//   SCHED_SLICE_NS  -- max time slice per task in nanoseconds (default: 5ms)
//   SCHED_PREEMPT   -- allow preemption (0 = off, 1 = on)

#include <scx/common.bpf.h>

// --- Compile-time tunables (AI engine injects these) ------------------------
#ifndef SCHED_SLICE_NS
#define SCHED_SLICE_NS  (5ULL * 1000000)   /* 5ms default */
#endif

#ifndef SCHED_PREEMPT
#define SCHED_PREEMPT   0
#endif

// --- BPF data structures -----------------------------------------------------

// A per-CPU FIFO queue holding task pointers
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __type(value, u32);   /* store pid */
} task_queue SEC(".maps");

// Per-task metadata stored in a hash map
struct task_meta {
    u64 enqueue_time;   /* timestamp when task was enqueued */
    u32 priority;       /* 0 = normal, higher = more important */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);         /* pid */
    __type(value, struct task_meta);
} task_meta_map SEC(".maps");

// Stats map for telemetry -- read by the MCP server
struct sched_stats {
    u64 tasks_enqueued;
    u64 tasks_dispatched;
    u64 avg_wait_ns;
    u64 preemptions;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct sched_stats);
} stats_map SEC(".maps");

// --- sched_ext operations ----------------------------------------------------

// Called when a task becomes runnable (wakeup or fork)
SEC("struct_ops/fifo_enqueue")
void BPF_STRUCT_OPS(fifo_enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;
    u64 now = bpf_ktime_get_ns();

    // Store metadata
    struct task_meta meta = {
        .enqueue_time = now,
        .priority     = 0,
    };
    bpf_map_update_elem(&task_meta_map, &pid, &meta, BPF_ANY);

    // Add to FIFO queue
    bpf_map_push_elem(&task_queue, &pid, BPF_EXIST);

    // Update stats
    u32 key = 0;
    struct sched_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
    if (stats)
        __sync_fetch_and_add(&stats->tasks_enqueued, 1);
}

// Called by the kernel to pick the next task to run
SEC("struct_ops/fifo_dispatch")
void BPF_STRUCT_OPS(fifo_dispatch, s32 cpu, u64 prev_sum_exec_runtime)
{
    u32 pid;
    u64 now = bpf_ktime_get_ns();

    // Pop oldest task from FIFO queue
    if (bpf_map_pop_elem(&task_queue, &pid) < 0)
        return;  /* nothing to run */

    // Look up the task struct from pid
    struct task_struct *p = bpf_task_from_pid(pid);
    if (!p)
        return;

    // Calculate wait time for stats
    struct task_meta *meta = bpf_map_lookup_elem(&task_meta_map, &pid);
    if (meta) {
        u64 wait_ns = now - meta->enqueue_time;
        u32 key = 0;
        struct sched_stats *stats = bpf_map_lookup_elem(&stats_map, &key);
        if (stats) {
            __sync_fetch_and_add(&stats->tasks_dispatched, 1);
            // Exponential moving average for wait time
            stats->avg_wait_ns = (stats->avg_wait_ns * 7 + wait_ns) / 8;
        }
    }

    // Dispatch: give the task its time slice
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCHED_SLICE_NS, 0);
    bpf_task_release(p);
}

// Called when a task finishes its time slice or is preempted
SEC("struct_ops/fifo_runnable")
void BPF_STRUCT_OPS(fifo_runnable, struct task_struct *p, u64 enq_flags)
{
    // Re-enqueue the task if preemption is enabled
#if SCHED_PREEMPT
    u32 pid = p->pid;
    bpf_map_push_elem(&task_queue, &pid, BPF_EXIST);
#endif
}

// Called when a new task is created
SEC("struct_ops/fifo_init_task")
s32 BPF_STRUCT_OPS(fifo_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    return 0;  /* allow all tasks */
}

// Exit: called when the scheduler is unloaded
SEC("struct_ops/fifo_exit")
void BPF_STRUCT_OPS(fifo_exit, struct scx_exit_info *ei)
{
    bpf_printk("SchedAI FIFO scheduler unloaded: %s\n", ei->msg);
}

// --- Scheduler class registration --------------------------------------------
SEC(".struct_ops.link")
struct sched_ext_ops fifo_ops = {
    .enqueue        = (void *)fifo_enqueue,
    .dispatch       = (void *)fifo_dispatch,
    .runnable       = (void *)fifo_runnable,
    .init_task      = (void *)fifo_init_task,
    .exit           = (void *)fifo_exit,
    .timeout_ms     = 5000,   /* watchdog: fallback to CFS after 5s stall */
    .name           = "schedai_fifo",
};

char _license[] SEC("license") = "GPL";
