#!/usr/bin/python3
#   Filename: buckethunter.py
#   Module: BucketHunter
#   Author: Andreas Georgiou (@superhedgy) & Jacob Wilkin (Greenwolf @jacob_wilkin)

# External Libraries
import colorama
import requests
from colorama import Fore, Style
from tld import get_tld
import traceback
import os



def cprint(type, msg, reset):
    colorama.init()
    message = {
        "action": Fore.YELLOW,
        "positive": Fore.GREEN + Style.BRIGHT,
        "info": Fore.YELLOW,
        "reset": Style.RESET_ALL,
        "red": Fore.RED,
        "white": Fore.WHITE,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW
    }
    style = message.get(type.lower())

    if type == "error":
        print("{0}\n[*] Error: {1}".format(Fore.RED + Style.BRIGHT, Style.RESET_ALL + Fore.WHITE + msg))
    else:
        print(style + msg, end="")
    if (reset == 1):
        print(Style.RESET_ALL)


def passive_query(hostx, key):
    keywords = get_tld(hostx.primary_domain, as_object=True, fail_silently=True, fix_protocol=True).domain
    # print(keywords)
    par = {'access_token': key, 'keywords': keywords}
    try:
        # Check if proxy is set, if it is dont verify ssl
        if 'http_proxy' in os.environ:
            response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets", params=par, timeout=5,verify=False)
        else:
            response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets", params=par, timeout=5)

        gwf_api = response.json()

        if gwf_api["buckets_count"] > 0:
            try:
                for bucket in gwf_api["buckets"]:
                    # print(bucket["bucket"])
                    hostx.buckets.append(bucket["bucket"])
            except:
                pass

    except:
        cprint("error", "[*] Error: connecting with GrayHatWarfare API for Keywords Search", 1)
        traceback.print_exc()

    par = {'access_token': key, 'keywords': hostx.orgName}
    try:
        if 'http_proxy' in os.environ:
            response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets", params=par, timeout=5,verify=False)
        else:
            response = requests.get("https://buckets.grayhatwarfare.com/api/v1/buckets", params=par, timeout=5)
        gwf_api = response.json()
        if gwf_api["buckets_count"] > 0:
            try:
                for bucket in gwf_api["buckets"]:
                    hostx.buckets.append(bucket["bucket"])
            except:
                pass

    except:
        cprint("error", "[*] Error: connecting with GrayHatWarfare API for OrgName Search", 1)
        traceback.print_exc()


def active(mswitch, hostx, wordlist, recursive=False):
    pass
