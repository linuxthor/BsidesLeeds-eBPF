import sys, ctypes
from bcc import BPF

class notify_t(ctypes.Structure):
    _fields_ = [("pid", ctypes.c_uint64),
                ("data", ctypes.c_uint8*4096),]

def handle_event(cpu, data, size):
    try:
        notify = ctypes.cast(data, ctypes.POINTER(notify_t)).contents
        data_s = ctypes.cast(notify.data, ctypes.c_char_p).value
        print("({}) {}: {}".format(cpu, notify.pid, data_s))
    except KeyboardInterrupt:
        sys.exit(0)

b = BPF(src_file = "mkdir_s_perf.c")
b["output"].open_perf_buffer(handle_event)
while True:
    try:
        b.kprobe_poll()
    except KeyboardInterrupt:
        sys.exit(0)

