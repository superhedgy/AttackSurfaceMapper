#!/usr/bin/python3
#   Filename: whois_collector.py
#   Module: Whois Collector
#   Author: Andreas Georgiou (@superhedgy)

# External Libraries
from ipwhois import IPWhois


def wlookup(hostx):
    for ip in hostx.resolved_ips:
        try:
            ip_object = IPWhois(ip.address)
            query = ip_object.lookup_rdap(depth=1)
            #            hostx.whois.append(query)
            #            net_sec = query.get('network', {})
            ip.location = query.get('asn_country_code')
            ip.asn = query.get('asn')
            ip.cidr = query.get('asn_cidr')
        #            print("Executed")
        #            print(query['network']['name'])
        except:
            pass
