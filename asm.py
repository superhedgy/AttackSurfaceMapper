#!/usr/bin/python3
#
#    /$$$$$$          /$$$$$$        /$$      /$$
#   /$$__  $$        /$$__  $$      | $$$    /$$$
#  | $$  \ $$       | $$  \__/      | $$$$  /$$$$
#  | $$$$$$$$       |  $$$$$$       | $$ $$/$$ $$
#  | $$__  $$        \____  $$      | $$  $$$| $$
#  | $$  | $$        /$$  \ $$      | $$\  $ | $$
#  | $$  | $$       | $$$$$$/       | $$ \/  | $$
#  |__/  |__/ TTACK \______/ URFACE |__/     |__/ APPER v1.0
#
#  Andreas Georgiou (@superhedgy)
#  Jacob Wilkin (@jacob_wilkin)
#
# Example:
# $python3 asm.py -t example.com -ln
#

# Standard Libraries
import argparse
import ipaddress
import json
import os
import signal
import socket
import sys
from datetime import datetime
from time import time, sleep
from urllib import parse

# External Libraries
import colorama
import pymongo
import requests
from colorama import Fore, Style
from netaddr import IPNetwork
from validator_collection import checkers

# ASM Modules
from modules import buckethunter
from modules import dnsdumpster
from modules import hosthunter
from modules import hunterio
from modules import linkedinner
from modules import screencapture
from modules import shodan
from modules import subhunter
from modules import urlscanio
from modules import weleakinfo
from modules import whois_collector

# Constants
__author__ = " Andreas Georgiou (@superhedgy)\n\t Jacob Wilkin (@greenwolf)"
__version__ = "v1.0"


# Classes
class TargetIP:
    def __init__(self, addr):
        self.address = addr
        self.hostname = []
        self.ports = []
        self.asn = ""
        self.asn_name = ""
        self.whois = []
        self.server = ""
        self.vulns = []
        self.cidr = ""
        self.location = ""
        self.country = ""


class Target:
    def __init__(self):
        self.primary_domain = ""
        self.subdomains = []
        self.orgName = ""
        self.dnsrecords = []
        self.buckets = []
        self.mx = None
        self.spf = None
        self.dmarc = []
        self.dmarc_status = ""
        self.emails = []
        self.guessed_emails = []
        self.creds = []
        self.hashes = []
        self.breaches = {}
        self.employees = []
        self.pattern = "{f}{last}"  # Default Email Pattern
        self.urls = []
        self.ipv4 = False
        self.resolved_ips = []


class Counter:
    def __init__(self):
        Counter.targets = 0
        Counter.ports = 0
        Counter.hostnames = 0
        Counter.subdomains = 0
        Counter.urls = 0
        Counter.buckets = 0
        Counter.sc = 0
        Counter.employees = 0
        Counter.intel = 0
        Counter.ips = 0
        Counter.vulns = 0
        Counter.emails = 0
        Counter.guessed_emails = 0
        Counter.creds = 0
        Counter.hashes = 0


class MasterSwitch:
    def __init__(self):
        self.shodan = True
        self.hunterio = True
        self.whois_collector = True
        self.subhunter = True
        self.dnsdumpster = True
        self.urlscanio = True
        self.weleakinfo = True
        self.weleakinfo_private = True
        self.screencapture = True
        self.webscraper = True
        self.linkedinner = False
        self.expand = False
        self.stealth = False
        self.verbose = False


# Print ACII Banner
def showbanner():
    print('''
  /$$$$$$          /$$$$$$        /$$      /$$
 /$$__  $$        /$$__  $$      | $$$    /$$$
| $$  \ $$       | $$  \__/      | $$$$  /$$$$
| $$$$$$$$       |  $$$$$$       | $$ $$/$$ $$
| $$__  $$        \____  $$      | $$  $$$| $$
| $$  | $$        /$$  \ $$      | $$\  $ | $$
| $$  | $$       | $$$$$$/       | $$ \/  | $$
|__/  |__/ TTACK \______/ URFACE |__/     |__/ APPER ''' + __version__)
    print("\nAuthors:" + __author__ + "\n")
    exit


def init_checks(master_switch, outpath):
    global args
    # Argument Parser
    parser = argparse.ArgumentParser(description='|<------ AttackSurfaceMapper - Help Page ------>|',
                                     epilog="Authors:" + __author__ + "\n\n ",
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-f", "--format", help="Choose between CSV and TXT output file formats.", default="csv")
    parser.add_argument("-o", "--output", help="Sets the path of the output file.", type=str, default=outpath)
    parser.add_argument("-sc", "--screen-capture", help="Capture a screen shot of any associated Web Applications.",
                        action="store_true", default=False)
    parser.add_argument("-sth", "--stealth", help="Passive mode allows reconaissaince using OSINT techniques only.",
                        action="store_true", default=False)
    parser.add_argument("-t", "--target", help="Set a single target IP.")
    parser.add_argument("targets", nargs='?', help="Sets the path of the target IPs file.", type=str, default="")
    parser.add_argument("-V", "--version", help="Displays the current version.", action="store_true", default=False)
    parser.add_argument("-w", "--wordlist", help="Specify a list of subdomains.", type=str,
                        default="resources/bitquark_top100k_sublist.txt")
    parser.add_argument("-sw", "--subwordlist", help="Specify a list of child subdomains.", type=str,
                        default="resources/top1000_sublist.txt")
    parser.add_argument("-e", "--expand", help="Expand the target list recursively.", action="store_true",
                        default=False)
    parser.add_argument("-ln", "--linkedinner", help="Extracts emails and employees details from linkedin.",
                        action="store_true", default=False)
    parser.add_argument("-v", "--verbose", help="Verbose ouput in the terminal window.", action="store_true",
                        default=False)

    args = parser.parse_args()

    #    if args.format.lower() != "txt" and args.format.lower() != "csv":
    #        print ("\nUnrecognised file format argument. Choose between 'txt' or 'csv' output file formats.\n")
    #        print("Example Usage: python3 asm.py targets.txt -f txt ")
    #        exit()

    if not (args.target or args.targets):
        cprint("error", "Please specify a single target or a list of targets.", 1)
        cprint("info", "Example Usage: python3 asm.py -t superhedgy.com", 1)
        exit()

    if args.version:
        print("HostHunter version", __version__)
        print("Author:", __author__)
        exit()

    if args.target and args.targets:
        cprint("error", "Too many arguments! Either select single target or specify a list of targets.", 1)
        cprint("info", "Example Usage: python3 asm.py -t superhedgy.com", 1)
        exit()
    # Targets Input File
    if args.targets and not os.path.exists(args.targets):
        cprint("error", "Targets file \"" + args.targets + "\" does not exist", 1)
        exit()

    if args.wordlist is None or args.wordlist == "":
        cprint("error", "Wordlist file argument is empty", 1)
        exit()

    if args.subwordlist is None or args.subwordlist is "":
        cprint("error", "Wordlist file argument is empty", 1)
        exit()

    if args.wordlist and not os.path.exists(args.wordlist):
        cprint("error", "Wordlist file \"" + str(args.wordlist) + "\" does not exist", 1)
        exit()

    if args.subwordlist and not os.path.exists(args.subwordlist):
        cprint("error", "SubWordlist file \"" + str(args.subwordlist) + "\" does not exist", 1)
        exit()

    if args.output and os.path.exists(args.output):
        cprint("info", "\n[?] {0} file already exists, would you like to overwrite it?".format(args.output), 1)
        while True:
            answer = input(
                Fore.WHITE + "[" + Fore.RED + Style.BRIGHT + ">" + Style.RESET_ALL + Fore.WHITE + "]" + Fore.WHITE + " Answer with [Y]es or [N]o : ").lower()
            if answer.startswith("n"):
                exit()
            elif answer.startswith("y"):
                break

    print(Style.RESET_ALL)

    # Checks for a Internet Connection
    try:
        socket.setdefaulttimeout(5)
        socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("8.8.8.8", 53))  # Google DNS IPv4
    except:
        try:
            socket.setdefaulttimeout(8)
            socket.socket(socket.AF_INET, socket.SOCK_STREAM).connect(("208.69.38.205", 53))  # OpenDNS IPv4
        except:
            cprint("white", "\n" + 82 * "*", 0)
            cprint("error", "No Internet Connection! Ensure that you are online and run ASM again.", 0)
            print(82 * "*" + "\n")
            exit(1)

    if args.expand:
        cprint("info", "\n[!] Expand Mode Enabled, out-of-scope targets might be included.\n", 1)  # Success Msg
        master_switch.expand = True
        sleep(0.5)

    if args.verbose:
        master_switch.verbose = True

    return args.output


# MongoDB
mongo_client = pymongo.MongoClient('localhost', 27017)
db = mongo_client.asm
store_targets = db.targets


# Resolve Domain Function - Returns a list
def asn_expansion(mswitch, hostx):
    cprint("info", "[i] Searching for ASNs based on: " + hostx.orgName, 1)
    answer3 = input(
        Fore.WHITE + "[" + Fore.RED + Style.BRIGHT + ">" + Style.RESET_ALL + Fore.WHITE + "]" + "[EXPAND-MODE]" + Fore.WHITE + " Enter Company Name: ")
    print(Style.RESET_ALL)
    if answer3 == "":
        asn_query = parse.quote(hostx.orgName)
    else:
        asn_query = parse.quote(answer3)

    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
    api_endpoint = "https://api.bgpview.io/search?query_term=" + asn_query
    try:
        response = requests.get(api_endpoint, headers=user_agent)
        api = json.loads(response.text)
    except:
        cprint("error", "Attack surface expansion failed.", 1)
        return -1
    asns = []
    prefixes = []

    if response.status_code is 200:
        try:
            for item in api['data']['asns']:
                # print (item)
                if mswitch.verbose is True:
                    print(60 * "*")
                    print("ASN: " + str(item["asn"]))
                    print("ASN Name: " + item.get("name"))
                    print("Description: " + item["description"])
                    print("Location: " + item["country_code"])
                    print(60 * "*")
                asns.append(item["asn"])
        except:
            cprint("error", "Attack surface expansion failed.", 1)
            return -1

        try:
            for item in api['data']['ipv4_prefixes']:

                if mswitch.verbose is True:
                    print(60 * "*")
                    print("CIDR: " + item["ip"] + "/" + str(item["cidr"]))
                    print("Prefix Name: " + item.get("name"))
                    print("Prefix Description: " + item["description"])
                    print("Location: " + item["country_code"])
                    print(60 * "*")

                prefixes.append(item["prefix"])
        except:
            cprint("error", "Attack surface expansion failed while searching for IPv4 prefixes.", 1)
            return -1

        if len(asns) > 0:
            for asn in asns:
                try:
                    response2 = requests.get("https://api.bgpview.io/asn/{0}/prefixes".format(str(asn)),
                                             headers=user_agent)
                    api2 = json.loads(response2.text)
                    # print(response2.text)
                    print(api2["data"]["ipv4_prefixes"])
                    if response2.status_code is 200:
                        try:
                            for item in api2["data"]["ipv4_prefixes"]:
                                # print (item)
                                if mswitch.verbose is True:
                                    cprint("info", "Expanding prefix:" + str(item["prefix"]), 1)
                                prefixes.append(item["prefix"])
                        except:
                            cprint("error", "Attack surface expansion failed.", 1)
                            return -1
                except:
                    return -1

        if len(prefixes) > 0:
            for prefix in prefixes:
                if mswitch.verbose is True:
                    cprint("info", "[i] Adding IPv4 Prefix to the targets list:" + prefix, 1)
                for ip in IPNetwork(prefix):
                    tmp = TargetIP(ip)
                    if ip not in hostx.resolved_ips:
                        hostx.resolved_ips.append(tmp)


# Resolve Domain Function - Returns a list
def resolve_domain(domain):
    try:
        resolve = socket.gethostbyname_ex(domain)
        IP = resolve[2]
        return IP
    except Exception:
        return ""


# validate Funciton - Validates IP
def add_target_domain(list_domain, input_domain, validated_input):
    input_domain = input_domain.replace("\n", "")
    if not input_domain:
        return 0

    t = Target()
    # Valid Input IPv4
    if checkers.is_ipv4(input_domain):
        if ipaddress.ip_address(input_domain).is_private:
            cprint("error", '"' + input_domain + '"' + " is a Private IPv4 address", 1)
            return 0
        else:
            validated_input.append(input_domain)
            return 0
    # Valid Input Domain
    elif checkers.is_domain(input_domain):
        validated_input.append(input_domain)
        t.ipv4 = False
        t.primary_domain = input_domain
        associated_ips = resolve_domain(t.primary_domain)
        # if not associated_ips:
        #     return 0
        if len(associated_ips) > 0:
            for x in associated_ips:
                tmp = TargetIP(x)
                if not ipaddress.ip_address(x).is_private:
                    t.resolved_ips.append(tmp)

        if t.primary_domain in list_domain.keys():
            cprint("info", "[i] Target Not Added - Domain {0} Exists".format(t.primary_domain), 1)
            pass
        else:
            list_domain[t.primary_domain] = t
            cprint("info", "[i] Target [{0}] Added.".format(t.primary_domain), 1)
    else:
        cprint("error", input_domain + " is not a valid IPv4 address or Domain Name", 1)
        return 0


def add_target_ip(target_list, IP):
    validated_input = []  # Dummy list
    tmp = TargetIP(IP)

    # Validate IPv4 Input Address
    if checkers.is_ipv4(IP):
        if ipaddress.ip_address(IP).is_private:
            return 0

        for key in target_list.keys():
            # print("Key: "+key)
            for x in target_list[key].resolved_ips:
                if (IP == x.address):
                    cprint("info", "Target Not Added - Address {0} already exists.".format(IP), 1)
                    return 0

        domain = urlscanio.get_domain(IP)
        if domain:
            add_target_domain(list, domain, validated_input)
            try:
                target_list[domain].resolved_ips.append(tmp)
            except:
                pass
        # Create a List with Unsorted IPs
        # add_target_domain(list,"",validated_input)


# keyloader Function - Load API Keys
def keyloader(keychain, master_switch):
    keyfile = open("keylist.asm", "rt")  # Read keylist.asm File

    for line in keyfile:
        tmp = line.split()
        keychain[tmp[0]] = tmp[2].replace("\"", "")

    print("{0}   HostHunter Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
    master_switch.hosthunter = True

    if args.screen_capture:
        print("{0}   ScreenCapture Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.screencapture = True
    else:
        print("{0}   ScreenCapture Module	: [{1}Disabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.RED, Fore.WHITE, Style.RESET_ALL))
        master_switch.screencapture = False
    print("{0}   DNSdumpster Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN + Style.BRIGHT, Fore.WHITE, Style.RESET_ALL))
    print("{0}   URLScanIO Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))

    if len(keychain["linkedin_username"]) > 0 and len(keychain["linkedin_password"]) and args.linkedinner:
        print("{0}   LinkedInner Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.linkedinner = True
    else:
        print("{0}   LinkedInner Module	: [{1}Disabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.RED, Fore.WHITE, Style.RESET_ALL))
        master_switch.linkedinner = False

    if len(keychain["hunterio"]) == 40:
        print("{0}   HunterIO Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.hunterio = True
    else:
        print("{0}   HunterIO Module	: [{1}Disabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.RED, Fore.WHITE, Style.RESET_ALL))
        master_switch.hunterio = False

    if len(keychain["shodan"]) == 32:
        print("{0}   Shodan Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.shodan = True
    else:
        print("{0}   Shodan Module	: [{1}Disabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.RED, Fore.WHITE, Style.RESET_ALL))
        master_switch.shodan = False

    if len(keychain["virustotal"]) == 64:
        print(
            "{0}   VirusTotal Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.virustotal = True
    else:
        print(
            "{0}   VirusTotal Module	: [{1}Disabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.RED, Fore.WHITE, Style.RESET_ALL))
        master_switch.virustotal = False

    if len(keychain["weleakinfo_priv"]) == 40:
        print(
            "{0}   WeLeakInfo Module	: [{1}Enabled{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))
        master_switch.weleakinfo_private = True
    else:
        print("   WeLeakInfo Module	: [Disabled]")
        master_switch.weleakinfo_private = False

    if args.expand:
        print("{0}   SubHunter Module	: [{1}Recursive{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.YELLOW, Fore.WHITE, Style.RESET_ALL))
        master_switch.subhunter = True
    else:
        print("{0}   SubHunter Module	: [{1}Active{2}]{3}".format(Fore.WHITE + Style.BRIGHT, Fore.GREEN, Fore.WHITE, Style.RESET_ALL))


# msave Function - Store output in MongoDB [UAT]
def msave(t):
    mtarget = {
        "Address": t.address,
        "ASN": t.asn,
        "Hostnames": t.hname,
        "Apps": t.urls,
        "IPv6": t.ipv6,
        "CIDR": t.cidr
    }
    store_targets.insert_one(mtarget)
    print("Stored")


# cprint Function - Prints Coloured Messages
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
    if reset == 1:
        print(Style.RESET_ALL)


# Print Results Function -
def store_results(hostx, output_path):
    results_path = output_path + "/" + hostx.primary_domain

    try:
        os.mkdir(results_path)
    except:
        pass

    emails_filepath = results_path + "/" + 'emails.txt'
    emails_file = open(emails_filepath, 'w')

    usernames_filepath = results_path + "/" + 'usernames.txt'
    usernames_file = open(usernames_filepath, 'w')

    creds_filepath = results_path + "/" + 'creds.txt'
    creds_file = open(creds_filepath, 'w')

    hashes_filepath = results_path + "/" + 'hashes.txt'
    hashes_file = open(hashes_filepath, 'w')

    subs_filepath = results_path + "/" + 'subdomains.txt'
    subs_file = open(subs_filepath, 'w')

    dns_filepath = results_path + "/" + 'dns_records.txt'
    dns_file = open(dns_filepath, 'w')

    employees_filepath = results_path + "/" + 'employees.txt'
    employees_file = open(employees_filepath, 'w')

    targetips_filepath = results_path + "/" + 'target_ips.csv'
    targetips_file = open(targetips_filepath, 'w')

    buckets_filepath = results_path + "/" + 's3buckets.txt'
    buckets_file = open(buckets_filepath, 'w')

    spoofchecks_filepath = results_path + "/" + 'email_spoof_checks.txt'
    spoofchecks_file = open(spoofchecks_filepath, 'w')

    for email in hostx.emails:
        emails_file.write(email + '\n')

    for email in hostx.emails:
        usernames_file.write(email.split('@', 1)[0] + '\n')

    for cred in hostx.creds:
        creds_file.write(cred + '\n')

    for hash in hostx.hashes:
        hashes_file.write(hash + '\n')

    for sub in hostx.subdomains:
        subs_file.write(sub + '\n')

    for record in hostx.dnsrecords:
        dns_file.write(record + '\n')

    for bucket in hostx.buckets:
        buckets_file.write(bucket + '\n')

    spoofchecks_file.write("Target : " + hostx.primary_domain + '\n')
    spoofchecks_file.write("SPF : " + str(hostx.spf) + '\n')
    spoofchecks_file.write("DMARC Status : " + hostx.dmarc_status + '\n')
    spoofchecks_file.write("DMARC Record : " + '\n')
    for record in hostx.dmarc:
        spoofchecks_file.write(record + '\n')

    if len(hostx.employees) > 0:
        for employee in hostx.employees:
            employees_file.write(employee[0] + "," + employee[1] + "," + employee[2] + "," + employee[3] + "\n")

    # Write Header
    targetips_file.write(
        "\"" + "IP Address" + "\",\"" + "Port/Protocol" + "\",\"" + "ASN" + "\",\"" + "ASN Description" + "\",\"" + "Vulnerabities" + "\",\"" + "Location" + "\"\n")
    for ip in hostx.resolved_ips:
        targetips_file.write("\"" + ip.address + "\",\"" + ", ".join(
            map(str, ip.ports)) + "\",\"" + ip.asn + "\",\"" + ip.asn_name + "\",\"" + ", ".join(
            map(str, ip.vulns)) + "\",\"" + ip.location + "\"\n")


# Print Results Function - Terminal Output
def print_results(count1, stime):
    ttime = round(time() - stime, 2)
    cprint("green", "\n" + "-" * 80, 1)
    print(Fore.YELLOW + "\n[%] Analysed {0} Targets in {1} sec".format(
        Fore.RED + Style.BRIGHT + str(count1.targets) + Style.RESET_ALL + Fore.YELLOW,
        Fore.WHITE + Style.BRIGHT + str(ttime) + Fore.YELLOW))
    print(Fore.WHITE + Style.BRIGHT + "\n[%] Discovered:" + Style.RESET_ALL)
    print(" {0} IPs".format(Fore.RED + Style.BRIGHT + str(count1.ips) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Open Ports".format(Fore.RED + Style.BRIGHT + str(count1.ports) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Hostnames".format(Fore.RED + Style.BRIGHT + str(count1.hostnames) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Subdomains".format(Fore.RED + Style.BRIGHT + str(count1.subdomains) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Vulnerabities".format(Fore.RED + Style.BRIGHT + str(count1.vulns) + Style.RESET_ALL + Fore.WHITE))
    print(Fore.WHITE + Style.BRIGHT + "\n[%] Intelligence Extracted:" + Style.RESET_ALL)
    print(" {0} WeLeakInfo Credentials".format(
        Fore.RED + Style.BRIGHT + str(count1.creds) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Emlpoyees' Details".format(
        Fore.RED + Style.BRIGHT + str(count1.employees) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} AWS Buckets Discovered".format(
        Fore.RED + Style.BRIGHT + str(count1.buckets) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Email Addresses".format(Fore.RED + Style.BRIGHT + str(count1.emails) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Guessed Emails".format(
        Fore.RED + Style.BRIGHT + str(count1.guessed_emails) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Credentials".format(Fore.RED + Style.BRIGHT + str(count1.creds) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Password Hashes".format(Fore.RED + Style.BRIGHT + str(count1.hashes) + Style.RESET_ALL + Fore.WHITE))
    print(" {0} Screenshots {1}".format(Fore.RED + Style.BRIGHT + str(count1.sc) + Style.RESET_ALL + Fore.WHITE,
                                        Style.RESET_ALL))
    cprint("green", "\n" + "-" * 80, 1)


# Main Function
def main(keychain, switch, output_path, count):
    validated_input = []
    targets = []
    target_list = dict()  # Creates a Dict of targets
    unsorted_ips = dict()  # Creates a Dict of Unsorted IPs
    if args.target:
        targets.append(args.target)
    else:
        targets = open(args.targets, "rt")  # Read File

    # Add Domain Name Targets
    for line in targets:
        if line == "" or line == "\n":
            continue
        if not add_target_domain(target_list, line, validated_input):
            continue
    # End of For Loop

    # Add IPv4 Targets
    for line in validated_input:
        if not add_target_ip(target_list, line):
            continue
    # End of For Loop

    # Debug Functionality
    if switch.verbose is True:
        for k in target_list.keys():
            print("*************************")
            print("Targets Dictionary Key:", k)
            for x in target_list[k].resolved_ips:
                print(">> " + x.address)
            print("*************************")

    # Iterates Through the Target List
    for key in target_list.keys():

        # [B] Target - Domain Name - Execution Flow
        cprint("white", "\n[+] Target Domain: ", 0)
        cprint("red", target_list[key].primary_domain, 1)

        for ip in target_list[key].resolved_ips:
            cprint("white", "	|", 1)
            cprint("white", "  [{0}]".format(ip.address), 1)

        if switch.expand is True:
            subhunter.active(switch, target_list[key], args.wordlist, args.subwordlist, recursive=True)  # Passive
        else:
            subhunter.active(switch, target_list[key], args.wordlist, args.subwordlist,
                             recursive=False)  # Passive Recursive Depth=2

        # HTTP Based
        if switch.stealth is False:
            hosthunter.active(target_list[key], count)  # Active

        # IP Based
        if switch.shodan is True:
            shodan.port_scan(target_list[key], keychain["shodan"], count)  # Passive

        if switch.whois_collector is True and switch.stealth is False:
            whois_collector.wlookup(target_list[key])  # Active

        # hosthunter.query_api(target_list[key]) # Passive
        hosthunter.org_finder(target_list[key])  # Passive

        buckethunter.passive_query(target_list[key], keychain["grayhatwarfare"])  # Passive

        if switch.expand is True:
            asn_expansion(target_list[key])  # Passive

        # Domain Based
        hosthunter.dnslookup(target_list[key])  # Passive
        urlscanio.query(target_list[key])  # Passive

        if switch.virustotal is True:
            subhunter.passive_query(target_list[key], keychain["virustotal"])  # Passive

        if switch.stealth is not True:
            # start_time = time()
            # ttime = round(time() - start_time,2)
            # print("Time Took " + str(ttime) + "s")
            hosthunter.dnsquery(target_list[key])  # Active

        if switch.hunterio is True:
            hunterio.query(target_list[key], keychain["hunterio"])

        map_path = dnsdumpster.get_map(target_list[key], output_path)  # Passive

        if (args.screen_capture and not args.stealth):
            screencapture.main(target_list[key], output_path)

        if len(target_list[key].orgName) > 0:
            print("\n {0}|| Organisation Name : {1}".format(Fore.WHITE,
                                                            Fore.YELLOW + target_list[key].orgName + Style.RESET_ALL))

        if switch.linkedinner is True:
            answer2 = input(
                Fore.WHITE + "[" + Fore.RED + Style.BRIGHT + ">" + Style.RESET_ALL + Fore.WHITE + "]" + Fore.WHITE + " Enter Company Name / Company ID: ")
            if answer2.isdigit() and len(answer2) > 0:
                cprint("info", "  [i] Searching Linkedin with CompanyID: " + answer2, 1)
                # LinkedInUsername, linkedin_password, company_name, companyid
                # BBC 1762
                linkedinner.get_emails_for_company_name(switch, target_list[key], keychain["linkedin_username"],
                                                        keychain["linkedin_password"], "", answer2)
            elif not answer2.isdigit() and len(answer2) > 0:
                cprint("info", "  [i] Searching Linkedin with Company Name: " + answer2, 1)
                linkedinner.get_emails_for_company_name(switch, target_list[key], keychain["linkedin_username"],
                                                        keychain["linkedin_password"], answer2, 0)
            elif len(target_list[key].orgName) > 0:
                cprint("info", "  [i] Searching Linkedin with Company Name: " + target_list[key].orgName.replace(",",
                                                                                                                 "").replace(
                    ".", ""), 1)
                answer2 = str(
                    target_list[key].orgName.replace(",", "").replace(".", "").replace(" ", "%20").replace(" LLC",
                                                                                                           "").replace(
                        " LTD", ""))
                linkedinner.get_emails_for_company_name(switch, target_list[key], keychain["linkedin_username"],
                                                        keychain["linkedin_password"], answer2, 0)
            else:
                cprint("error", "Linkedinner module has been disabled. No valid input was detected.", 1)

        if switch.weleakinfo_private is True:
            weleakinfo.query(target_list[key], keychain["weleakinfo"], keychain["weleakinfo_priv"])  # Passive
            weleakinfo.priv_api(target_list[key], keychain["weleakinfo"], keychain["weleakinfo_priv"])  # Passive

        if len(target_list[key].subdomains) > 0:
            print(Fore.WHITE + " || Subdomains: " + Fore.YELLOW + str(
                len(target_list[key].subdomains)) + Style.RESET_ALL)
            for i in range(len(target_list[key].subdomains)):
                cprint("info", target_list[key].subdomains[i], 0)
                if i > 50:
                    if len(target_list[key].subdomains) > 50:
                        cprint("info", "\n...", 1)
                    else:
                        cprint("info", "", 1)
                    break
                if i == (len(target_list[key].subdomains)) - 1:
                    cprint("info", "", 1)
                else:
                    cprint("info", ",", 0)

        if len(target_list[key].emails) > 0:
            print(Fore.WHITE + " || Emails: " + Fore.YELLOW + str(len(target_list[key].emails)) + Style.RESET_ALL)
            for i in range(len(target_list[key].emails)):
                cprint("yellow", target_list[key].emails[i], 0)
                if i > 50:
                    if len(target_list[key].emails) > 50:
                        cprint("yellow", "\n...", 1)
                    else:
                        cprint("info", "", 1)
                    break
                if i == (len(target_list[key].emails)) - 1:
                    cprint("info", "", 1)
                else:
                    cprint("info", ",", 0)

        if len(target_list[key].guessed_emails) > 0:
            print(Fore.WHITE + " || Guessed Emails: " + Fore.YELLOW + str(
                len(target_list[key].guessed_emails)) + Style.RESET_ALL)
            for i in range(len(target_list[key].guessed_emails)):
                cprint("yellow", target_list[key].guessed_emails[i], 0)
                if i > 50:
                    if len(target_list[key].guessed_emails) > 50:
                        cprint("yellow", "\n...", 1)
                    else:
                        cprint("info", "", 1)
                    break
                if i == (len(target_list[key].guessed_emails)) - 1:
                    cprint("info", "", 1)
                else:
                    cprint("info", ",", 0)

        if len(target_list[key].breaches) > 0:
            cprint("white", " || WeLeakInfo Data Breaches: ", 1)
            for email, breach in target_list[key].breaches.items():
                cprint("yellow", "{0} : {1}".format(email, breach), 1)

        if len(target_list[key].creds) > 0:
            cprint("white", " || WeLeakInfo Credentials Discovered: ", 0)
            cprint("info", "" + str(len(target_list[key].creds)), 1)
            for i in range(len(target_list[key].creds)):
                cprint("yellow", target_list[key].creds[i], 1)
                if i > 8:
                    if len(target_list[key].creds) > 8:
                        cprint("yellow", "...", 1)
                    break

        if len(target_list[key].hashes) > 0:
            cprint("white", " || WeLeakInfo Hashes Discovered: ", 0)
            cprint("info", "" + str(len(target_list[key].hashes)), 1)
            for i in range(len(target_list[key].hashes)):
                cprint("yellow", target_list[key].hashes[i], 1)
                if i > 8:
                    if len(target_list[key].hashes) > 5:
                        cprint("yellow", "...", 1)
                    break

        if len(target_list[key].buckets) > 0:
            cprint("white", " || AWS Buckets Discovered: ", 0)
            cprint("info", "" + str(len(target_list[key].buckets)), 1)
            for i in range(len(target_list[key].buckets)):
                cprint("yellow", target_list[key].buckets[i], 1)
                if i > 5:
                    if len(target_list[key].buckets) > 5:
                        cprint("yellow", "\n...", 1)
                    break

        print(" {0}|| DNS Records : {1}".format(Fore.WHITE,
                                                Fore.YELLOW + str(len(target_list[key].dnsrecords)) + Style.RESET_ALL))
        for i in range(len(target_list[key].dnsrecords)):
            cprint("yellow", target_list[key].dnsrecords[i], 1)
            if i > 2:
                if len(target_list[key].dnsrecords) > 2:
                    cprint("info", "...", 1)
                break

        if target_list[key].mx is not None:
            cprint("white", " || MX Records	:", 1)
            for dt in target_list[key].mx:
                cprint("info", str(dt.exchange), 1)

        if target_list[key].spf is not None:
            if target_list[key].spf:
                print(
                    " {0}|| SPF	: {1}".format(Fore.WHITE, Fore.GREEN + str(target_list[key].spf) + Style.RESET_ALL))
            else:
                print(" {0}|| SPF	: {1}".format(Fore.WHITE, Fore.RED + Style.BRIGHT + str(
                    target_list[key].spf) + Style.RESET_ALL))

        if len(target_list[key].dmarc) > 0:
            print(
                " {0}|| DMARC : {1}".format(Fore.WHITE, Fore.GREEN + target_list[key].dmarc_status + Style.RESET_ALL))
        else:
            print(" {0}|| DMARC : {1}".format(Fore.WHITE, Fore.RED + Style.BRIGHT + "False" + Style.RESET_ALL))

        # if len(target_list[key].pattern) > 0:
        #     print (" || Email Pattern Detected : {0}".format(Fore.RED+Style.BRIGHT+email.pattern+Style.RESET_ALL))

        print(" {0}|| dnsDumpster Map: {1}".format(Fore.WHITE, Fore.YELLOW + str(map_path) + Style.RESET_ALL))

        if args.screen_capture:
            print(
                Fore.WHITE + " || Screenshots: " + Fore.YELLOW + os.getcwd() + output_path + "/screenshots" + Style.RESET_ALL)

        # Scan each IP pointing to the same domain
        for ip in target_list[key].resolved_ips:
            print("")
            print(Fore.WHITE + " [-] IP Address: " + Style.BRIGHT + Fore.YELLOW + str(ip.address) + Style.RESET_ALL)
            if ip.hostname:
                print(Fore.WHITE + " 	|| Hostname: " + Fore.YELLOW + ','.join(map(str, ip.hostname)) + Style.RESET_ALL)
            if ip.server:
                print(Fore.WHITE + " 	|| Server: " + Fore.YELLOW + ip.server)
            if ip.ports:
                print(Fore.WHITE + " 	|| Ports: " + Fore.YELLOW + '/tcp, '.join(map(str, ip.ports)) + "/tcp" + Style.RESET_ALL)
            if ip.vulns:
                print(Fore.WHITE + " 	|| Possible Vulnerabities: " + Fore.YELLOW + ','.join(map(str, ip.vulns)) + Style.RESET_ALL)
            if ip.location:
                print(Fore.WHITE + " 	|| Location: " + Fore.YELLOW + ip.location + Style.RESET_ALL)
            print(Fore.WHITE + " 	|| ASN: " + Fore.YELLOW + ip.asn + Style.RESET_ALL)
            if ip.asn_name:
                print(Fore.WHITE + " 	|| ASN Name: " + Fore.YELLOW + str(ip.asn_name) + Style.RESET_ALL)
            print(Fore.WHITE + " 	|| CIDR: " + Fore.YELLOW + ip.cidr + Style.RESET_ALL)
            print("")
            if ip.ports:
                count.ports += len(ip.ports)
            if ip.vulns:
                count.vulns += len(ip.vulns)

        # Update Counters
        count.ips += len(target_list[key].resolved_ips)
        count.targets += 1
        count.subdomains += len(target_list[key].subdomains)
        count.employees += len(target_list[key].employees)
        count.emails += len(target_list[key].emails)
        count.guessed_emails += len(target_list[key].guessed_emails)
        count.creds += len(target_list[key].creds)
        count.hashes += len(target_list[key].hashes)
        count.buckets += len(target_list[key].buckets)

        store_results(target_list[key], output_path)


# Capture SIGINT
def sig_handler(signal, frame):
    cprint("info", "\n\n[i] Shutting down AttackSurfaceMapper. . .\n", 1)  # Success Msg
    try:
        signal.pause()
    except:
        pass
    cprint("info", "\n[i] Bye, bye!\n", 1)  # Success Msg
    sys.exit(0)


if __name__ == "__main__":

    signal.signal(signal.SIGINT, sig_handler)  # Signal Listener
    now = datetime.now()
    output_path = 'asm_run_' + str(datetime.now().strftime("%d.%m.%y_%H-%M-%S"))
    sw1 = MasterSwitch()
    keychain = dict()
    c1 = Counter()
    start_time = time()  # Start Counter

    output_path = init_checks(sw1, output_path)  # Initialisation Checks
    showbanner()  # Banner
    keyloader(keychain, sw1)  # Key Loader

    cprint("info", "\n\n[i] AttackSurfaceMapper is running. . .\n", 1)  # Success Msg

    if not os.path.exists(output_path):
        os.mkdir(output_path)

    main(keychain, sw1, output_path, c1)

    print_results(c1, start_time)  # Print terminal output

    exit()
