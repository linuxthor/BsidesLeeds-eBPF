import sys
import ctypes
import base64
import socket
from bcc import BPF
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch()

prog = """
    #include <asm/ptrace.h>
    #include <bcc/proto.h>
    #include <linux/fs.h>
    #include <linux/binfmts.h>

    BPF_PERF_OUTPUT(output);

    typedef struct notify {
        uint64_t pid;
        unsigned long ino; 
        char buf[BINPRM_BUF_SIZE];
        char fna[4096];
        char itp[4096];
    } notify_t;
    BPF_PERCPU_ARRAY(notify_array, notify_t, 1);

    int kprobe__load_script(struct pt_regs *ctx, struct linux_binprm *bprm)
    {
        int i = 0;
        notify_t* n = notify_array.lookup(&i);
        struct file *file; 
        struct inode *inode;

        if(!n)
        {
            return 0; 
        }

        i = bpf_probe_read_str(&n->buf, BINPRM_BUF_SIZE, bprm->buf);
        if(n->buf[0] == '#') // is this really a script? 
        {
            file = bprm->file; 
            inode= file->f_inode;
            n->ino = inode->i_ino; 
            bpf_probe_read(&n->fna, 4096, bprm->filename);
            bpf_probe_read(&n->itp, 4096, bprm->interp);
            n->pid = (u32)bpf_get_current_pid_tgid();
            output.perf_submit(ctx, n, sizeof(notify_t));
        }
        return 0; 
    }
"""
class notify_t(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint64),
                ("ino", ctypes.c_uint64),
                ("buf", ctypes.c_uint8*128),
                ("fna", ctypes.c_uint8*4096),
                ("itp", ctypes.c_uint8*4096),]
    
def handle_event(cpu, data, size):
    try:
        notify = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
        buf_s = ctypes.cast(notify.buf, ctypes.c_char_p).value
        bbuf_s = base64.b64encode(notify.buf)
        fna_s = ctypes.cast(notify.fna, ctypes.c_char_p).value
        itp_s = ctypes.cast(notify.itp, ctypes.c_char_p).value
        print("({}) {}: {} {} (via {} @ {})".format(cpu, notify.pid, bbuf_s, fna_s, itp_s, notify.ino))
        print("{}".format(buf_s))
        doc = {
            'hostname': socket.gethostname(),
            'pid': notify.pid,
            'inode': notify.ino,
            'application': fna_s,
            'interpreter': itp_s,
            'header': buf_s,
            'b64hed': bbuf_s,
            '@timestamp': datetime.now().isoformat(),
        }
        res = es.index(index="seclogs-binfmt-script", doc_type='launch-info',  body=doc)

    except KeyboardInterrupt:
        sys.exit(0)

b = BPF(text=prog)
b["output"].open_perf_buffer(handle_event)
while True:
    try:
        b.kprobe_poll()
    except KeyboardInterrupt:
        sys.exit(0)

