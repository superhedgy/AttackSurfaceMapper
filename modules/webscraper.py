#!/usr/bin/python3
#   Filename: webscraper.py
#   Module: webscraper
#   Author: Andreas Georgiou (@superhedgy)

# Standard Libraries
import re
 
# External Libraries
import requests
from bs4 import BeautifulSoup
import os

def extract_info(hostx):
    print("webscraper Enabled")
    url = "https://" + hostx.primary_domain
    user_agent = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36'}
    try:
        if 'http_proxy' in os.environ:
            response = requests.get(url, headers=user_agent,verify=False)
        else:
            response = requests.get(url, headers=user_agent)

        html_response = BeautifulSoup(response.text, 'html.parser')

        r = session.get(url)
        links = r.html.absolute_links
        print(links)
        # print (html_response)
        # print(html_response)

        phone = re.findall("((?:\d{3}|\(\d{3}\))?(?:\s|-|\.)?\d{3}(?:\s|-|\.)\d{4})", html_response.text)
        emails = re.findall(">[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,3}<", html_response.text)

        print("")
        # Emails
        print("")
        print("Emails Found:" + emails)

    except:
        pass
