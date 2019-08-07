#!/usr/bin/python3
#   Filename: buckethunter.py
#   Module: BucketHunter
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import socket,json
from tld import get_tld, get_fld
# BucketFinder Key 8c029e7589d8595e4758a17224009d97
# https://buckets.grayhatwarfare.com/api/v1/buckets/0/10?access_token=8c029e7589d8595e4758a17224009d97&keywords=test
# External Libraries


import requests

def passive_query(hostx,key):

    keywords = get_tld(hostx.primary_domain, as_object=True,fail_silently=True,fix_protocol=True).domain
    #print(keywords)
    par = {'access_token':key,'keywords':keywords}
    try:
        response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets",params=par,timeout=4)
        gwf_api = response.json()

        if gwf_api["buckets_count"] > 0:
            try:
                for bucket in gwf_api["buckets"]:
                    #print(bucket["bucket"])
                    hostx.buckets.append(bucket["bucket"])
            except:
                pass

    except:
        cprint ("error","[*] Error: connecting with GrayHatWarfare API",1)

    par = {'access_token':key,'keywords':hostx.orgName}
    try:
        response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets",params=par,timeout=4)
        gwf_api = response.json()
        if gwf_api["buckets_count"] > 0:
            try:
                for bucket in gwf_api["buckets"]:
                    hostx.buckets.append(bucket["bucket"])
            except:
                pass

    except:
        cprint ("error","[*] Error: connecting with GrayHatWarfare API",1)

def active(mswitch,hostx,wordlist,recursive=False):
    pass
