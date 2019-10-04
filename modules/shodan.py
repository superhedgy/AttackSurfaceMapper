#!/usr/bin/python3
#   Filename: shodan.py
#   Module: Shodan
#   Authors: Jacob Wilkin (Greenwolf @jacob_wilkin)
#            Andreas Georgiou (@superhedgy)

# Standard Libraries
import time

# External Libraries
import shodan


def port_scan(hostx, key, counter):
    if 'http_proxy' in os.environ:
        try:
            proxy_dict = {'https':os.environ['http_proxy']}
            #proxy_dict = {'http':os.environ['http_proxy'],'https':os.environ['http_proxy']}
            #print(proxy_dict)
            api = shodan.Shodan(key,proxies=proxy_dict)
        except:
            traceback.print_exc()
    else:
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
