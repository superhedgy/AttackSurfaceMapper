#!/usr/bin/python3
#   Filename: whois_collector.py
#   Module: Whois Collector
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import sys,os

# External Libraries
from ipwhois import IPWhois

def wlookup(hostx):
    for ip in hostx.resolved_ips:
        try:
            object = IPWhois(ip.address)
            query = object.lookup_rdap(depth=1)
#            hostx.whois.append(query)
#            net_sec = query.get('network', {})
            ip.location = query.get('asn_country_code')
            ip.asn = query.get('asn')
            ip.cidr = query.get('asn_cidr')
#            print("Executed")
#            print(query['network']['name'])
        except:
            pass
