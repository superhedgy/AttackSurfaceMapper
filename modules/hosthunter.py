#!/usr/bin/python3
#   Filename: hosthunter.py
#   Module: HostHunter
#   Author: Andreas Georgiou (@superhedgy)

import socket
import requests
# Standard Libraries
import ssl

# External Libraries
import OpenSSL
import dns.resolver
import requests
import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()


# ssl_grabber Function
def ssl_grabber(resolved_ip, port):
    try:
        cert = ssl.get_server_certificate((resolved_ip.address, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname = x509.get_subject().CN

        # Add New HostNames to List
        for host in cert_hostname.split('\n'):
            # print(host)
            if (host == "") or (host in resolved_ip.hostname):
                pass
            else:
                try:
                    resolved_ip.hostname.append(host)
                except:
                    pass
    except (urllib3.exceptions.ReadTimeoutError, requests.ConnectionError, urllib3.connection.ConnectionError,
            urllib3.exceptions.MaxRetryError, urllib3.exceptions.ConnectTimeoutError, urllib3.exceptions.TimeoutError,
            socket.error, socket.timeout) as e:
        pass


# r_dns Function
def r_dns(targetIP):
    try:
        hostname = socket.gethostbyaddr(targetIP.address)
        if hostname[0] != "":
            targetIP.hostname.append(hostname[0])
        # print("[Debug] r_dns result " + hostname[0]) ## Debug Statement
    except:
        pass


# query_api Function
def query_api(hostx):
    try:
        url = "https://api.hackertarget.com/reverseiplookup/?q="
        r2 = requests.get(url + hostx.resolved_ips[0].address, verify=False).text
        
        # Check for "No DNS A records found" or "API count exceeded" and "error"
        if ("No DNS A records found" not in r2) and ("API count exceeded" not in r2) and ("error" not in r2):
            for host in r2.split('\n'):
                if (host == "") or (host in hostx.hname):
                    pass
                else:
                    hostx.hname.append(host)
        else:
            pass
    except (requests.exceptions.ConnectionError, socket.error, socket.timeout) as e:
        print(f"Error: query_api failed, connecting with HackerTarget.com API. {e}")


def org_finder(hostx):
    target = hostx.primary_domain

    try:
        cert = ssl.get_server_certificate((target, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        orgName = x509.get_subject().organizationName
        unit = x509.get_subject().organizationalUnitName
        hostx.orgName = str(orgName)
    except:
        pass


#  dnsloopkup Function
def dnslookup(hostx):
    try:
        url = "https://api.hackertarget.com/dnslookup/?q="
        r2 = requests.get(url + hostx.primary_domain, verify=False).text
        
        # Check for "No DNS A records found" or "API count exceeded" and "error"
        if ("No DNS A records found" not in r2) and ("API count exceeded" not in r2) and ("error" not in r2):
            hostx.dnsrecords = r2.splitlines()
            # Check for SPF record
            for record in hostx.dnsrecords:
                word = record.rsplit(':')
                try:
                    if ("TXT" in word[0]) and ("v=spf1" in word[1]):
                        hostx.spf = True
                        break
                except:
                    pass
            hostx.spf = False if hostx.spf is None else True
    except (requests.exceptions.ConnectionError, socket.error, socket.timeout) as e:
        print(f"Error: dnslookup failed, connecting with HackerTarget.com API. {e}")



def check_dmarc_record(dmarc_record):
    # Parses a DMARC record and checks for restrictions on email spoofing.
    if "v=DMARC" in dmarc_record:
        if ";p=reject;" in dmarc_record:
            return "Primary Domain is not Spoofable. "
        elif ";p=quarantine;" in dmarc_record:
            return "Primary Domain accepts spoofed emails but they will be marked as suspicious. "
        elif ";p=none;" in dmarc_record:
            return "Primary Domain allows Email Spoofing. "
    else:
        return "Spoofable Email Domain."

def check_subdomain_spoofing(dmarc_record):
    # Checks a DMARC record for restrictions on email spoofing for subdomains.
    if ";sp=none;" in dmarc_record:
        return "Subdomains allow Email Spoofing."
    elif ";sp=reject;" in dmarc_record:
        return "SubDomains are not Spoofable."
    elif ";sp=quarantine;" in dmarc_record:
        return "SubDomains will accept spoofed emails but they will be marked as suspicious."

def dnsquery(hostx):
    # Retrieves DMARC and MX records for a given hostx object.
    try:
        response = dns.resolver.query('_dmarc' + '.' + hostx.primary_domain, 'TXT')
        for rdata in response:
            dmarc_record = str(rdata).replace(' ', '')
            hostx.dmarc_status = check_dmarc_record(dmarc_record)
            hostx.dmarc_status += check_subdomain_spoofing(dmarc_record)
            hostx.dmarc.append(str(rdata))
    except:
        hostx.dmarc = []

    try:
        hostx.mx = dns.resolver.query(hostx.primary_domain, 'MX')
    except:
        pass


def active(hostx, count):
    for ip in hostx.resolved_ips:
        ssl_grabber(ip, "443")  # SSL
        ssl_grabber(ip, "993")  # IMAP - SSL
        ssl_grabber(ip, "22")  # FTPs - SSL

        count.hostnames += len(ip.hostname)  # Updates Counter
