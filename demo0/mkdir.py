from bcc import BPF

prog = """
#include <asm/ptrace.h>

int kprobe__sys_mkdir(struct pt_regs *ctx, const char __user *pathname, umode_t mode)
{
    bpf_trace_printk("MKDIR CALLED\\n");
    return 0;
}
"""

b = BPF(text = prog)
b.trace_print()
