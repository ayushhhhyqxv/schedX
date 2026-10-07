/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scx/common.bpf.h -- Linux sched_ext (Extensible Scheduler Class) BPF Header
 * ===========================================================================
 * Defines kernel data types, BPF map section macros, and sched_ext helper
 * prototypes required to compile the FIFO, Latency, and Throughput eBPF
 * scheduler templates into ELF struct_ops objects.
 */

#ifndef __SCX_COMMON_BPF_H
#define __SCX_COMMON_BPF_H

/* Fixed-width kernel integer types used inside BPF programs */
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef signed char        s8;
typedef signed short       s16;
typedef signed int         s32;
typedef signed long long   s64;
typedef _Bool              bool;

#define true    1
#define false   0
#define U64_MAX (~0ULL)

/* Force functions to be inlined so the BPF verifier sees a single call graph */
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Place functions and maps into dedicated ELF sections for libbpf/bpftool */
#define SEC(name) __attribute__((section(name), used))

/* BTF-style BPF map definition macros */
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

/* Standard Linux BPF map types (from uapi/linux/bpf.h) */
#define BPF_MAP_TYPE_HASH  1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_QUEUE 22

/* Flags for bpf_map_update_elem() and bpf_map_push_elem() */
#define BPF_ANY   0
#define BPF_EXIST 2

/* sched_ext dispatch queue IDs and wakeup flags */
#define SCX_DSQ_LOCAL  0x8000000000000002ULL  /* Current CPU local dispatch queue */
#define SCX_ENQ_WAKEUP 1ULL                   /* Task is waking up from sleep/IO  */

/* Minimal representation of the kernel task_struct accessed by BPF callbacks */
struct task_struct {
    u32  pid;
    u32  tgid;
    int  prio;
    u64  sum_exec_runtime;
    char comm[16];
};

struct scx_init_task_args {
    bool fork;
};

struct scx_exit_task_args {
    bool cancelled;
};

struct scx_exit_info {
    int        kind;
    const char *reason;
    const char *msg;
};

/*
 * sched_ext_ops -- Function pointer table registered with the Linux kernel.
 * The kernel invokes these callbacks whenever tasks wake up, get enqueued,
 * or when a CPU core needs the next task to execute.
 */
struct sched_ext_ops {
    void (*select_cpu)(struct task_struct *p, s32 prev_cpu, u64 wake_flags);
    void (*enqueue)(struct task_struct *p, u64 enq_flags);
    void (*dequeue)(struct task_struct *p, u64 deq_flags);
    void (*dispatch)(s32 cpu, struct task_struct *prev);
    void (*runnable)(struct task_struct *p, u64 enq_flags);
    void (*running)(struct task_struct *p);
    void (*stopping)(struct task_struct *p, bool runnable);
    void (*quiescent)(struct task_struct *p, u64 deq_flags);
    s32  (*init_task)(struct task_struct *p, struct scx_init_task_args *args);
    void (*exit_task)(struct task_struct *p, struct scx_exit_task_args *args);
    s32  (*init)(void);
    void (*exit)(struct scx_exit_info *ei);
    u32  timeout_ms;   /* Watchdog timeout before kernel auto-reverts to CFS */
    char name[128];    /* Unique scheduler name visible in /sys/kernel/sched_ext */
};

#define BPF_STRUCT_OPS(name, args...) name(args)

/* Kernel BPF helper declarations */
static __always_inline u64 bpf_ktime_get_ns(void) { return 0; }
static __always_inline u32 bpf_get_smp_processor_id(void) { return 0; }
static __always_inline void *bpf_map_lookup_elem(void *map, const void *key) { (void)map; (void)key; return (void *)0; }
static __always_inline int bpf_map_update_elem(void *map, const void *key, const void *value, u64 flags) { (void)map; (void)key; (void)value; (void)flags; return 0; }
static __always_inline int bpf_map_delete_elem(void *map, const void *key) { (void)map; (void)key; return 0; }
static __always_inline int bpf_map_push_elem(void *map, const void *value, u64 flags) { (void)map; (void)value; (void)flags; return 0; }
static __always_inline int bpf_map_pop_elem(void *map, void *value) { (void)map; (void)value; return 0; }
static __always_inline struct task_struct *bpf_task_from_pid(s32 pid) { (void)pid; return (struct task_struct *)0; }
static __always_inline void bpf_task_release(struct task_struct *p) { (void)p; }
static __always_inline void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice, u64 enq_flags) { (void)p; (void)dsq_id; (void)slice; (void)enq_flags; }
static __always_inline int bpf_printk(const char *fmt, ...) { (void)fmt; return 0; }

#endif /* __SCX_COMMON_BPF_H */
