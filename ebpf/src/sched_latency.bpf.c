// SPDX-License-Identifier: GPL-2.0
// SchedAI - Latency-Optimized eBPF Scheduler Template
//
// Strategy: Prioritize tasks with the shortest recent CPU burst (SJF-inspired).
// Best for: Interactive workloads, gaming, audio, real-time apps.
//
// AI-tunable parameters:
//   LATENCY_WEIGHT    -- how aggressively to prefer short tasks (1-10)
//   IO_BOOST          -- nanoseconds of priority boost for recently I/O-woken tasks
//   PREEMPT_THRESH_NS -- if a task runs longer than this, preempt it

#include <scx/common.bpf.h>

#ifndef LATENCY_WEIGHT
#define LATENCY_WEIGHT    5
#endif

#ifndef IO_BOOST
#define IO_BOOST          (2ULL * 1000000)   /* 2ms boost */
#endif

#ifndef PREEMPT_THRESH_NS
#define PREEMPT_THRESH_NS (3ULL * 1000000)   /* 3ms preemption threshold */
#endif

// --- Data structures ----------------------------------------------------------

struct task_vtime {
    u64 vruntime;       /* virtual runtime -- lower means higher priority */
    u64 last_run_ns;    /* when the task last ran */
    u8  io_woken;       /* 1 if recently woken from I/O wait */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, u32);
    __type(value, struct task_vtime);
} vtime_map SEC(".maps");

// Priority queue: min-heap ordered by vruntime
// We use a sorted array approximation for simplicity
struct pq_entry {
    u64 vruntime;
    u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct pq_entry);
} pq_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);   /* pq size */
} pq_size SEC(".maps");

// --- Scheduler operations -----------------------------------------------------

SEC("struct_ops/lat_enqueue")
void BPF_STRUCT_OPS(lat_enqueue, struct task_struct *p, u64 enq_flags)
{
    u32 pid = p->pid;
    u64 now = bpf_ktime_get_ns();

    struct task_vtime *vt = bpf_map_lookup_elem(&vtime_map, &pid);
    u64 vruntime;

    if (vt) {
        vruntime = vt->vruntime;
        // Apply I/O boost: recently woken tasks get lower vruntime = higher priority
        if (vt->io_woken && (enq_flags & SCX_ENQ_WAKEUP)) {
            vruntime = (vruntime > IO_BOOST) ? vruntime - IO_BOOST : 0;
            vt->io_woken = 0;
        }
    } else {
        // New task: start at current minimum vruntime
        vruntime = now;
        struct task_vtime new_vt = {
            .vruntime    = vruntime,
            .last_run_ns = now,
            .io_woken    = 0,
        };
        bpf_map_update_elem(&vtime_map, &pid, &new_vt, BPF_ANY);
    }

    // Insert into priority queue
    u32 key = 0;
    u32 *size = bpf_map_lookup_elem(&pq_size, &key);
    if (size && *size < 4095) {
        struct pq_entry entry = { .vruntime = vruntime, .pid = pid };
        bpf_map_update_elem(&pq_map, size, &entry, BPF_ANY);
        __sync_fetch_and_add(size, 1);
    }
}

SEC("struct_ops/lat_dispatch")
void BPF_STRUCT_OPS(lat_dispatch, s32 cpu, u64 prev_sum_exec_runtime)
{
    // Find task with minimum vruntime (linear scan -- OK for <=4096 tasks)
    u32 key = 0;
    u32 *size_ptr = bpf_map_lookup_elem(&pq_size, &key);
    if (!size_ptr || *size_ptr == 0) return;

    u32 size = *size_ptr;
    u64 min_vrt = U64_MAX;
    u32 min_idx = 0;
    u32 min_pid = 0;

    // BPF loop limit: up to 512 iterations
    for (u32 i = 0; i < 512 && i < size; i++) {
        struct pq_entry *e = bpf_map_lookup_elem(&pq_map, &i);
        if (e && e->vruntime < min_vrt) {
            min_vrt = e->vruntime;
            min_idx = i;
            min_pid = e->pid;
        }
    }

    if (min_pid == 0) return;

    // Remove from queue (swap with last entry)
    u32 last_idx = size - 1;
    struct pq_entry *last = bpf_map_lookup_elem(&pq_map, &last_idx);
    if (last) {
        bpf_map_update_elem(&pq_map, &min_idx, last, BPF_ANY);
        __sync_fetch_and_add(size_ptr, -1);
    }

    // Dispatch selected task
    struct task_struct *p = bpf_task_from_pid(min_pid);
    if (!p) return;

    // Update vruntime
    u64 now = bpf_ktime_get_ns();
    struct task_vtime *vt = bpf_map_lookup_elem(&vtime_map, &min_pid);
    if (vt) {
        vt->vruntime += PREEMPT_THRESH_NS / LATENCY_WEIGHT;
        vt->last_run_ns = now;
    }

    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, PREEMPT_THRESH_NS, 0);
    bpf_task_release(p);
}

SEC("struct_ops/lat_init_task")
s32 BPF_STRUCT_OPS(lat_init_task, struct task_struct *p,
                   struct scx_init_task_args *args)
{
    u32 pid = p->pid;
    struct task_vtime vt = {
        .vruntime    = bpf_ktime_get_ns(),
        .last_run_ns = 0,
        .io_woken    = 0,
    };
    bpf_map_update_elem(&vtime_map, &pid, &vt, BPF_ANY);
    return 0;
}

SEC("struct_ops/lat_exit")
void BPF_STRUCT_OPS(lat_exit, struct scx_exit_info *ei)
{
    bpf_printk("SchedAI Latency scheduler unloaded\n");
}

SEC(".struct_ops.link")
struct sched_ext_ops latency_ops = {
    .enqueue    = (void *)lat_enqueue,
    .dispatch   = (void *)lat_dispatch,
    .init_task  = (void *)lat_init_task,
    .exit       = (void *)lat_exit,
    .timeout_ms = 3000,
    .name       = "schedai_latency",
};

char _license[] SEC("license") = "GPL";
