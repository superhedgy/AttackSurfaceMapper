#!/usr/bin/python3
#   Filename: hosthunter.py
#   Module: HostHunter
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import sys,os
import ssl
import socket
import re
import time
import dns.resolver

# External Libraries
import OpenSSL
import urllib3
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_OPTIONAL
context.load_default_certs()
#socket.setdefaulttimeout(3)

# sslGrabber Function
def sslGrabber(resolvedIP,port):
    try:
        cert=ssl.get_server_certificate((resolvedIP.address, port))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        cert_hostname=x509.get_subject().CN

        # Add New HostNames to List
        for host in cert_hostname.split('\n'):
            #print(host)
            if (host=="") or (host in resolvedIP.hostname):
                pass
            else:
                try:
                    resolvedIP.hostname.append(host)
                except:
                    pass
    except (urllib3.exceptions.ReadTimeoutError,requests.ConnectionError,urllib3.connection.ConnectionError,urllib3.exceptions.MaxRetryError,urllib3.exceptions.ConnectTimeoutError,urllib3.exceptions.TimeoutError,socket.error,socket.timeout) as e:
        pass

# rDNS Function
def rDNS(targetIP):
    try:
        hostname = socket.gethostbyaddr(targetIP.address)
        if hostname[0] is not "":
                targetIP.hostname.append(hostname[0])
        # print("[Debug] rDNS result " + hostname[0]) ## Debug Statement
    except:
        pass

# queryAPI Function
def queryAPI(hostx):
    try:
        url = "https://api.hackertarget.com/reverseiplookup/?q="
        r2 = requests.get(url+hostx.resolved_ips[0].address,verify=False).text
        if (r2.find("No DNS A records found")==-1) and (r2.find("API count exceeded")==-1 and r2.find("error")==-1):
            for host in r2.split('\n'):
                if (host=="") or (host in hostx.hname):
                    pass
                else:
                    hostx.hname.append(host)
        # Add API count exceed detection
        else:
            pass
    except (requests.exceptions.ConnectionError,urllib3.connection.ConnectionError,urllib3.exceptions.ConnectTimeoutError,urllib3.exceptions.MaxRetryError,urllib3.exceptions.TimeoutError,socket.error,socket.timeout) as e:
        print ("error","queryAPI failed, connecting with HackerTarget.com API",1)

def orgFinder(hostx):
    target = hostx.primary_domain

    try:
        cert=ssl.get_server_certificate((target, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        orgName=x509.get_subject().organizationName
        unit = x509.get_subject().organizationalUnitName
        hostx.orgName = str(orgName)

    except:
        pass

#  dnsloopkup Function
def dnslookup(hostx):
    try:
        url = "https://api.hackertarget.com/dnslookup/?q="
        r2 = requests.get(url+hostx.primary_domain,verify=False).text
        if (r2.find("No DNS A records found")==-1) and (r2.find("API count exceeded")==-1 and r2.find("error")==-1):
            hostx.dnsrecords=r2.splitlines()
            # Add API count exceed detection
            for record in hostx.dnsrecords:
                word = record.rsplit('\t')
                if (word[4] == "TXT") and ("v=spf1" in word[5]):
                    hostx.spf = True
            if hostx.spf is None:
                hostx.spf = False
        else:
            pass
    except (requests.exceptions.ConnectionError,urllib3.connection.ConnectionError,urllib3.exceptions.ConnectTimeoutError,urllib3.exceptions.MaxRetryError,urllib3.exceptions.TimeoutError,socket.error,socket.timeout) as e:
        print ("error"," dnslookup failed, connecting with HackerTarget.com API",1)

def dnsquery(hostx):
    try:
        response = dns.resolver.query('_dmarc' + '.' + hostx.primary_domain,'TXT')

        for rdata in response:
            dmarc_record = str(rdata).replace(' ','')
            if "v=DMARC" in dmarc_record:
                if ";p=reject;" in dmarc_record:
                    hostx.dmarc_status = "Primary Domain is not Spoofable. "
                elif ";p=quarantine;" in dmarc_record:
                    hostx.dmarc_status = "Primary Domain accepts spoofed emails but they will be marked as suspicious. "
                elif ";p=none;" in dmarc_record:
                    hostx.dmarc_status = "Primary Domain allows Email Spoofing. "

                if ";sp=none;" in dmarc_record:
                    hostx.dmarc_status += "Subdomains allow Email Spoofing."
                elif ";sp=reject;" in dmarc_record:
                    hostx.dmarc_status += "SubDomains are not Spoofable."
                elif ";sp=quarantine;" in dmarc_record:
                    hostx.dmarc_status += "SubDomains will accept spoofed emails but they will be marked as suspicious."
            else:
                hostx.dmarc_status = "Spoofable Email Domain."

            hostx.dmarc.append(str(rdata))
    except:
        hostx.dmarc = []

    try:
        hostx.mx = dns.resolver.query(hostx.primary_domain, 'MX')
    except:
        pass

def active(hostx,count):
    for ip in hostx.resolved_ips:
        sslGrabber(ip,"443") # SSL
        sslGrabber(ip,"993") # IMAP - SSL
        sslGrabber(ip,"22") # FTPs - SSL

        count.hostnames+=len(ip.hostname) #Updates Counter
