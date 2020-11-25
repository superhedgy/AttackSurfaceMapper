#!/usr/bin/python3
#   Filename: censys.py
#   Module: Censys
#   Authors: Censys Team (support@censys.io)
#            Aidan Holland (@thehappydinoa)

# Standard Libraries
import time

# External Libraries
from censys.ipv4 import CensysIPv4

__version__ = "v1.0"

def port_scan(hostx, censys_id, censys_secret, counter):
    c = CensysIPv4(censys_id, censys_secret)

    for ip in hostx.resolved_ips:
        try:
            response = c.view(ip.address)
            ip.ports = response["ports"]
            counter.ports = counter.ports + len(hostx.ports)
        except:
            time.sleep(1)
            continue
