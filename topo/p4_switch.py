#!/usr/bin/env python3
"""Mininet node classes that run a bmv2 simple_switch.

A P4Switch launches one `simple_switch` process bound to its Mininet veth
interfaces, using the Mininet port numbers directly as bmv2 port numbers so
that the control-plane table entries (generated from the same port numbers)
line up.

The switch is started with node.popen() (a real subprocess) rather than the
pty-based node.cmd("... &"): backgrounding a long-running process through
Mininet's pty monitor wedges net.start() on this Mininet 2.3.0 / WSL2 setup.
popen() returns immediately and gives a clean handle to wait on.
"""
import os
import time
from sys import exit

from mininet.node import Switch, Host
from mininet.log import info, error, debug


SWITCH_START_TIMEOUT = 10  # seconds to wait for the thrift server


class P4Host(Host):
    """A plain host with NIC offload disabled (so crafted frames survive)."""

    def config(self, **params):
        r = super(P4Host, self).config(**params)
        intf = self.defaultIntf()
        intf.rename("%s-eth0" % self.name)
        for off in ("rx", "tx", "sg"):
            self.cmd("ethtool --offload %s-eth0 %s off" % (self.name, off))
        self.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        return r

    def describe(self):
        info("**** %s: %s\n" % (self.name, self.IP()))


class P4Switch(Switch):
    """A Mininet switch backed by a bmv2 simple_switch process."""

    device_id = 0

    def __init__(self, name, sw_path="simple_switch", json_path=None,
                 thrift_port=None, pcap_dump=False, log_dir="/tmp",
                 device_id=None, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.sw_path = sw_path
        self.json_path = json_path
        self.thrift_port = thrift_port
        self.pcap_dump = pcap_dump
        self.log_dir = log_dir
        self.proc = None
        self.logfd = None
        if device_id is not None:
            self.device_id = device_id
            P4Switch.device_id = max(P4Switch.device_id, device_id)
        else:
            self.device_id = P4Switch.device_id
            P4Switch.device_id += 1

    @classmethod
    def setup(cls):
        pass

    def check_switch_started(self, pid):
        """Wait until the thrift TCP port is listening (or the proc dies)."""
        for _ in range(SWITCH_START_TIMEOUT * 4):
            if not os.path.exists(os.path.join("/proc", str(pid))):
                return False
            listening = os.popen(
                "ss -ltn 2>/dev/null | grep -c ':%d '" % self.thrift_port
            ).read().strip()
            if listening and listening != "0":
                return True
            time.sleep(0.25)
        return False

    def start(self, controllers):
        info("Starting P4 switch %s (bmv2 dev %d)\n" % (self.name, self.device_id))
        args = [self.sw_path, "--device-id", str(self.device_id)]
        for port, intf in self.intfs.items():
            if intf.name != "lo":
                args.extend(["-i", "%d@%s" % (port, intf.name)])
        if self.pcap_dump:
            args.extend(["--pcap", self.log_dir])
        if self.thrift_port:
            args.extend(["--thrift-port", str(self.thrift_port)])
        args.append(self.json_path)

        logfile = os.path.join(self.log_dir, "%s.log" % self.name)
        info(" ".join(args) + "\n")
        self.logfd = open(logfile, "w")
        self.proc = self.popen(args, stdout=self.logfd, stderr=self.logfd)
        debug("P4 switch %s PID is %d\n" % (self.name, self.proc.pid))
        if not self.check_switch_started(self.proc.pid):
            error("P4 switch %s did not start (see %s)\n" % (self.name, logfile))
            exit(1)
        info("P4 switch %s thrift ready on :%d\n" % (self.name, self.thrift_port))

    def stop(self):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait()
            except Exception:
                pass
            self.proc = None
        if self.logfd is not None:
            try:
                self.logfd.close()
            except Exception:
                pass
            self.logfd = None
        self.deleteIntfs()

    def attach(self, intf):
        pass

    def detach(self, intf):
        pass
