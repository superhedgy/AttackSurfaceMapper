#!/usr/bin/python3
#   Filename: hunterio.py
#   Module: HunterIO
#   Author: Andreas Georgiou (@superhedgy)
# https://api.hunter.io/v2/domain-search?domain=

# Standard Libraries
import json

# External Libraries
import requests


def query(hostx, key):
    try:
        domain = hostx.primary_domain
        par = {'domain': domain, 'api_key': key}
        user_agent = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'}
        req = requests.get("https://api.hunter.io/v2/domain-search", params=par, headers=user_agent)
        hunterio_api = json.loads(req.text)

        try:
            for item in hunterio_api["data"]["emails"]:
                # print(item) # [Debug]: Prints Email Address
                hostx.emails.append(item["value"])
        except:
            pass

        try:
            hostx.pattern = hunterio_api["data"]["pattern"]
        except:
            pass

    except:
        pass
