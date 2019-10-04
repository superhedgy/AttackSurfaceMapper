#!/usr/bin/python3
#   Filename: subhunter.py
#   Module: SubHunter
#   Author: Andreas Georgiou (@superhedgy) & Jacob Wilkin (Greenwolf @jacob_wilkin)

# Standard Libraries
import colorama
import ipaddress
# External Libraries
import requests
from colorama import Fore, Style
from validator_collection import checkers

from modules import subbrute
import os


class TargetIP:
    def __init__(self, addr):
        self.address = addr
        self.hostname = []
        self.ports = []
        self.asn = ""
        self.asn_name = ""
        self.server = ""
        self.vulns = []
        self.cidr = ""
        self.location = ""
        self.country = ""


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
    par = {'apikey': key, 'domain': hostx.primary_domain}
    try:
        if 'http_proxy' in os.environ:
            response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=par, timeout=4,verify=False)
        else:
            response = requests.get("https://www.virustotal.com/vtapi/v2/domain/report", params=par, timeout=4)


        tv_api = response.json()

        try:
            for sibling in tv_api["domain_siblings"]:
                if (sibling in hostx.subdomains) or (sibling == ""):
                    pass
                else:
                    hostx.subdomains.append(sibling)
        except:
            pass

        try:
            for subdomain in tv_api["subdomains"]:
                if (subdomain in hostx.subdomains) or (subdomain == ""):
                    pass
                else:
                    hostx.subdomains.append(subdomain)
        except:
            pass
    except:
        cprint("error", "[*] Error: connecting with VirusTotal API", 1)


def active(mswitch, hostx, wordlist, subwordlist, recursive=False):
    for d in subbrute.run(hostx.primary_domain, subdomains=wordlist):
        if (d[0] in hostx.subdomains) or (d[0] is hostx.primary_domain) or ("REFUSED" in d[1]) or ("NOERROR" in d[1]):
            pass
        else:
            # Verbose Mode
            if mswitch.verbose is True:
                print(d[0] + "," + d[1] + "," + d[2])
            hostx.subdomains.append(d[0])
            if d[1] is "A":
                if checkers.is_ipv4(d[2]):
                    if ipaddress.ip_address(d[2]).is_private is False:
                        tmp = TargetIP(d[2])
                        tmp.hostname.append(d[0])
                        hostx.resolved_ips.append(tmp)
                        cprint("white", "	|", 1)
                        cprint("white", "  [{0}]".format(d[2]), 1)
                        if mswitch.verbose is True:
                            cprint("info", "[i] Adding target IPv4:" + d[2], 1)

    if recursive is True:
        for sub in hostx.subdomains:
            cprint("info", "[i] Enumerating: xxx." + sub, 1)
            for item in subbrute.run(sub, query_type="A", subdomains=subwordlist, process_count=50):
                if item[0] in hostx.subdomains or ("REFUSED" in item[1]) or ("NOERROR" in item[1]):
                    pass
                else:
                    # Verbose Mode
                    if mswitch.verbose is True:
                        print(item[0] + "," + item[1] + "," + item[2])
                    hostx.subdomains.append(item[0])
                    # print (d[0]) # [Debug] Prints succesfully resolved domain
