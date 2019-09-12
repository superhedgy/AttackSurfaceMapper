#!/usr/bin/python3
#   Filename: shodan.py
#   Module: Shodan
#   Authors: Andreas Georgiou (@superhedgy)
#            Jacob Wilkin (@greenwolf)

# Standard Libraries
import time

# External Libraries
import shodan


def port_scan(hostx, key, counter):
    api = shodan.Shodan(key)
    numports = 0

    for IP in hostx.resolved_ips:
        try:
            query = api.host(IP.address)
            IP.ports = query['ports']
            IP.vulns = query['vulns']
            IP.server = query['server']
            # print (query['vulnerabilities'])
            counter.ports = counter.ports + len(hostx.ports)
            counter.vulns = counter.vulns + len(hostx.vulns)
        except:
            time.sleep(1)
            continue
