import sys, ctypes, socket
from bcc import BPF
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch()

prog = """
    #include <asm/ptrace.h>
    #include <bcc/proto.h>
    #include <linux/limits.h>

    BPF_PERF_OUTPUT(output);

    typedef struct notify {
        uint64_t pid;
        char data[4096];
    } notify_t;
    BPF_PERCPU_ARRAY(notify_array, notify_t, 1);

    int probe_ap_send_error_response(struct pt_regs *ctx, void __user* req, int recurs)
    {
        int i = 0;

        struct request_rec {
            void * 	pool;
            void * 	connection;
            void * 	server;
            void * 	next;
            void * 	prev;
            void * 	main;
            char * 	the_request;
            int 	assbackwards;
            time_t 	request_time;
            char * 	status_line;
            int 	status;
            int 	method_number;
            char * 	method;
        };

        struct request_rec *request; 
        notify_t* n = notify_array.lookup(&i);

        if(!n)
        {
            return 0; 
        }

        request = (struct request_rec *)req; 
        bpf_probe_read_str(&n->data, 4096, request->the_request);
        n->pid = (u32)bpf_get_current_pid_tgid();
        output.perf_submit(ctx, n, sizeof(notify_t)); 
        return 0;
    }
"""
class notify_t(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint64),
                ("data", ctypes.c_uint8*4096),]

def handle_event(cpu, data, size):
    try:
        notify = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
        data_s = ctypes.cast(notify.data, ctypes.c_char_p).value
        print("({}) {} {}".format(cpu, notify.pid, data_s))
        doc = {
            'hostname': socket.gethostname(),
            'pid': notify.pid,
            'request': data_s, 
            '@timestamp': datetime.now().isoformat(),
        }
        res = es.index(index="apache-errors", doc_type='ap_error', body=doc)
    except KeyboardInterrupt:
        sys.exit(0)

b = BPF(text=prog)
b.attach_uprobe(name="/usr/sbin/apache2", sym="ap_send_error_response", fn_name="probe_ap_send_error_response", pid=-1)
b["output"].open_perf_buffer(handle_event)
while True:
    try:
        b.kprobe_poll()
    except KeyboardInterrupt:
        sys.exit(0)

