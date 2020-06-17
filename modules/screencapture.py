#!/usr/bin/python3
#   Filename: screencapture.py
#   Author: Andreas Georgiou (@superhedgy)
#   Credits: Code taken from HostHunter and adapted

# Standard Libraries

# External Libraries
import os

# External Libraries
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Selenium Configuration
chrome_opt = Options()
chrome_opt.add_argument("--ignore-certificate-errors")
chrome_opt.add_argument("--test-type")
chrome_opt.add_argument("--headless")  # Comment out to Debug
DRIVER = "chromedriver"


def main(hostx, out_path):
    sc_path = out_path + "/screenshots"

    if not os.path.exists(sc_path):
        os.mkdir(sc_path)

    take_screenshot(hostx.primary_domain, "443", sc_path)

    for ip in hostx.resolved_ips:
        for port in ip.ports:
            take_screenshot(ip.address, port, sc_path)

    for sub in hostx.subdomains:
        take_screenshot(sub, "443", sc_path)


def take_screenshot(target, port, path):
    driver = webdriver.Chrome(executable_path=DRIVER, options=chrome_opt)
    driver.set_page_load_timeout(9)

    if port == "443":
        url = "https://" + target
    else:
        url = "http://" + target + ':' + str(port)
    try:
        driver.get(url)
    except:
        # print ("[Debug] Failed while Fetching ",url) # Debug Functionality
        pass

    # print ("[Debug] source value: ",driver.page_source) # Debug Functionality
    try:
        driver.save_screenshot(path + "/" + target + "_" + port + ".png")
    except:
        pass
    finally:
        driver.delete_all_cookies()  # Clear Cookies
        driver.close()
        driver.quit()
