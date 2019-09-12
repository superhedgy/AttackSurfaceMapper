#!/usr/bin/python3
#   Filename: urlscanio.py
#   Module: URLScanIO Module
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import json

# External Libraries
import requests

import asm


def get_domain(IP):
    # print (ip.address)
    # $ curl -v --url "https://urlscan.io/api/v1/search?ip=<IP>"
    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
    try:
        response = requests.get('https://urlscan.io/api/v1/search?q=ip:' + IP, headers=user_agent)
        api = json.loads(response.text)
        if api['total'] == 0:
            return
        try:
            return api['results'][0]['page']['domain']
        except:
            pass
    except:
        pass


def query(hostx):
    # print(hostx.address)
    # curl -v --url "https://urlscan.io/api/v1/search?ip=148.251.165.186"
    for ip in hostx.resolved_ips:
        par = {'q': ip.address}
        # print (ip.address)
        user_agent = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
        try:
            response = requests.get("https://urlscan.io/api/v1/search", params=par, headers=user_agent)
            # print(response.status_code)
            # print(response.text)
            api = json.loads(response.text)
            if api['total'] == 0:
                return
            try:
                ip.location = api['results'][0]['page']['city'] + ", " + api['results'][0]['page']['country']
            except:
                pass

            try:
                ip.asn = api['results'][0]['page']['asn']
            except:
                pass

            try:
                ip.asn_name = api['results'][0]['page']['asnname']
            except:
                pass

            if ip.server == "":
                try:
                    ip.server = api['results'][0]['page']['server']
                except:
                    pass

            try:
                for item in api['results']:
                    if (item['page']['domain'] in hostx.hname) or (item['page']['domain'] == ""):
                        pass
                    else:
                        hostx.hname.append(item['page']['domain'])
            except:
                pass

        except:
            asm.cprint("error", "[*] Error: connecting with URLScanIO.com API", 1)
    return
