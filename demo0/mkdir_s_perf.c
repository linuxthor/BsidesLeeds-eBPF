#include <asm/ptrace.h>
#include <bcc/proto.h>

BPF_PERF_OUTPUT(output);

typedef struct notify {
    uint64_t pid; 
    char data[4096]; 
} notify_t;
BPF_PERCPU_ARRAY(notify_array, notify_t, 1); 

int kprobe__sys_mkdir(struct pt_regs *ctx, const char __user *pathname, umode_t mode)
{
    int i = 0; 
    notify_t* n = notify_array.lookup(&i);

    if(!n)
    {
        return 0;
    }
    bpf_probe_read_str(&n->data, 4096, pathname);
    n->pid = (u32)bpf_get_current_pid_tgid();
    output.perf_submit(ctx, n, sizeof(notify_t));
    return 0;
}


