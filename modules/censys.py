#!/usr/bin/python3
#   Filename: censys.py
#   Module: Censys
#   Authors: Censys Team (support@censys.io)
#            Aidan Holland (@thehappydinoa)

# Standard Libraries
import time

# External Libraries
from censys.search import CensysHosts

__version__ = "v2.0"

def port_scan(hostx, censys_id, censys_secret, counter):
    c = CensysHosts(censys_id, censys_secret)

    for ip in hostx.resolved_ips:
        try:
            response = c.view(ip.address)
            ports = response.get("ports", [])
            if ip.ports:
                ip.ports.update(ports)
            else:
                ip.ports = ports
            counter.ports = counter.ports + len(hostx.ports)
        except:
            time.sleep(1)
            continue
