#!/usr/bin/env python3
"""tests/udp.py -- UDP probes inside a (throwaway) network namespace, without iproute2.

  udp.py up [ADDR ...]          bring lo up and give lo each ADDR (/32) as an alias
  udp.py probe SRC [PORT]       listen on 0.0.0.0:PORT (default 7777), send ONE datagram
                                from SRC to 127.0.0.1:PORT, print RX or NORX
  udp.py stream SECS SRC ...    for SECS seconds send numbered datagrams (about 1000/s each)
                                from every SRC to 127.0.0.1:7777 and count what arrives;
                                print one line per SRC: "SRC sent=N received=M"

The sender binds to SRC (an address `up` configured), so the packet traverses the input
hook with that source address. Needs to run as root in a network namespace.
"""
import fcntl
import socket
import struct
import sys
import threading
import time

SIOCGIFFLAGS, SIOCSIFFLAGS, SIOCSIFADDR, SIOCSIFNETMASK = 0x8913, 0x8914, 0x8916, 0x891C
IFF_UP, IFF_RUNNING = 0x1, 0x40


def ifreq_addr(name, addr):
    return struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\0\0", socket.inet_aton(addr), b"\0" * 8)


def up(addrs):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH14x", b"lo", 0))[:18])[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP | IFF_RUNNING))
    for i, a in enumerate(addrs, 1):
        fcntl.ioctl(s, SIOCSIFADDR, ifreq_addr("lo:%d" % i, a))
        fcntl.ioctl(s, SIOCSIFNETMASK, ifreq_addr("lo:%d" % i, "255.255.255.255"))


def listener(port):
    l = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    l.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    l.bind(("0.0.0.0", port))
    return l


def probe(src, port):
    l = listener(port)
    l.settimeout(0.5)
    t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    t.bind((src, 0))
    t.sendto(b"x", ("127.0.0.1", port))
    try:
        data, frm = l.recvfrom(64)
        print("RX" if frm[0] == src else "RX from %s" % frm[0])
    except socket.timeout:
        print("NORX")


def stream(secs, srcs):
    l = listener(7777)
    l.settimeout(0.2)
    got = {s: set() for s in srcs}
    sent = {s: 0 for s in srcs}
    stop = threading.Event()

    def rx():
        while not stop.is_set():
            try:
                data, frm = l.recvfrom(64)
            except socket.timeout:
                continue
            got.setdefault(frm[0], set()).add(int(data))

    th = threading.Thread(target=rx)
    th.start()
    socks = []
    for s in srcs:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.bind((s, 0))
        socks.append((s, t))
    end = time.time() + secs
    n = 0
    while time.time() < end:
        for s, t in socks:
            t.sendto(b"%d" % n, ("127.0.0.1", 7777))
            sent[s] += 1
        n += 1
        time.sleep(0.001)
    time.sleep(0.3)
    stop.set()
    th.join()
    for s in srcs:
        print("%s sent=%d received=%d" % (s, sent[s], len(got[s])))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "up":
        up(sys.argv[2:])
    elif cmd == "probe":
        probe(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 7777)
    elif cmd == "stream":
        stream(float(sys.argv[2]), sys.argv[3:])
    else:
        sys.exit("usage: see the docstring")
