#!/usr/bin/python3
#   Filename: weleakinfo.py
#   Module: WeLeakInfo Module
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import json
import time
import traceback

# External Libraries
import requests

import asm


def query(hostx, api_key, priv_key):
    head = {
        'user-agent': "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        'authorization': "Bearer" + " " + api_key
    }

    if not hostx.emails:
        return 0

    ## Free API
    for email in hostx.emails:
        try:
            url = "https://api.weleakinfo.com/v3/public/email/" + email
            response = requests.get(url, headers=head)

            if not (response.status_code == 200):
                return -1

            api = json.loads(response.text)

            if api['Total'] == 0:
                return 0

            try:
                for item in api['Data']:
                    result = result + "," + item

                hostx.breaches[email] = result.replace(',', '', 1)
            except:
                pass

            # print (breaches.items())

        except:
            asm.cprint("error", "[*] Error: connecting with WeLeakInfo API", 1)

        time.sleep(2)

    return


def priv_api(hostx, api_key, priv_key):
    headers = {
        'User-agent': "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0",
        "Content-Type": "application/x-www-form-urlencoded",
        'authorization': "Bearer " + priv_key
    }

    try:
        api_endpoint = "https://api.weleakinfo.com/v3/search"
        query = {
            "limit": "1000",
            "offset": "",
            "query": "*" + "@" + hostx.primary_domain,
            "regex": "",
            "type": "email",
            "wildcard": "true"
        }

        response = requests.request("POST", api_endpoint, data=query, headers=headers)

        if response.status_code is not 200:
            return -1

        api = json.loads(response.text)

        if api['Total'] == 0:
            return 0

        try:
            for result in api['Data']:
                try:
                    # print(result['Password'])
                    # print(result['Email'])
                    hostx.creds.append(result['Email'] + "::" + result['Password'])

                    if result['Email'] not in hostx.emails:
                        hostx.emails.append(result['Email'])
                except:
                    pass

                try:
                    # print(result['Hash'])
                    # print(result['Email'])
                    hostx.hashes.append(result['Email'] + "::" + result['Hash'])

                    if result['Email'] not in hostx.emails:
                        hostx.emails.append(result['Email'])
                except:
                    pass
                # hostx.breaches[email] = result
        except:
            traceback.print_exc()
            pass

    except:
        return
