#!/usr/bin/python3
#   Filename: linkedinner.py
#   Module: LinkedInner
#   Author: Jacob Wilkin & Andreas Georgiou (@superhedgy)
#   Credits: linkedint & @greenwolf

#Standard Libraries
import sys,urllib,os,json,math,re,traceback
import http.cookiejar

# External Libraries
import ASM
import requests
from colorama import Fore,Style,Back
from trans import trans
from bs4 import BeautifulSoup
from validator_collection import checkers

def login(linkedin_username,linkedin_password):
    cookie_filename = "cookies.txt"
    cookiejar = http.cookiejar.MozillaCookieJar(cookie_filename)
    opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler(),urllib.request.HTTPHandler(debuglevel=0),urllib.request.HTTPSHandler(debuglevel=0),urllib.request.HTTPCookieProcessor(cookiejar))

    page = loadPage(opener, "https://www.linkedin.com/uas/login")
    parse = BeautifulSoup(page, "html.parser")
    csrf = ""
    for link in parse.find_all('input'):
        name = link.get('name')
        if name == 'loginCsrfParam':
            csrf = link.get('value')
    login_data = urllib.parse.urlencode({'session_key': linkedin_username, 'session_password': linkedin_password, 'loginCsrfParam': csrf})
    page = loadPage(opener,"https://www.linkedin.com/checkpoint/lg/login-submit", login_data)

    parse = BeautifulSoup(page, "html.parser")
    cookie = ""
    try:
        cookie = cookiejar._cookies['.www.linkedin.com']['/']['li_at'].value
    except:
        print("[DEBUG] Cookie Value")
        return
    cookiejar.save()
    os.remove(cookie_filename)
    return cookie


def authenticate(linkedin_username,linkedin_password):
    try:
        a = login(linkedin_username,linkedin_password)
        session = a
        if len(session) == 0:
            ASM.cprint("error","Unable to login to LinkedIn.com!",1)
            return
        ASM.cprint("info","  [i] Obtained a new LinkedIn session.",1)
        cookies = dict(li_at=session)
    except Exception as e:
        ASM.cprint("error","Could not authenticate to LinkedIn. %s" % e,1)
        return
    return cookies


def loadPage(client, url, data=None):
    try:
        if data is not None:
            response = client.open(url, data.encode("utf-8"))
        else:
            response = client.open(url)
        emptybyte = bytearray()
        return emptybyte.join(response.readlines())
    except:
        print("[DEBUG] LoadPage Function Failed:")
        traceback.print_exc()
        return

# Pass in company_id as 0 if you want to search, otherwise overwrite
def get_emails_for_company_name(mswitch,hostx,linkedin_username,linkedin_password,company_name,company_id):

    exit=False
    cookies = authenticate(linkedin_username,linkedin_password) # perform authentication
    if company_id is 0: # Don't find company id, use provided id from -cid or --companyid flag
        # code to get company ID based on name
        url = "https://www.linkedin.com/voyager/api/typeahead/hits?q=blended&query=%s" % company_name
        headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
        cookies['JSESSIONID'] = 'ajax:0397788525211216808'
        r = requests.get(url, cookies=cookies, headers=headers)
        content = json.loads(r.text)
        firstID = 0
        for i in range(0,len(content['elements'])):
            try:
                company_id = content['elements'][i]['hitInfo']['com.linkedin.voyager.typeahead.TypeaheadCompany']['id']
                if firstID == 0:
                    firstID = company_id
                if mswitch.verbose is True:
                    print("[!] Found company ID: %s for %s" % (company_id,company_name))
            except:
                continue
        company_id = firstID
        if company_id is 0:
            ASM.cprint("error","No valid Company ID found, please provide a company ID instead.",1)
            return

    ASM.cprint("info","  [i] Using company ID: " + str(company_id),1)
    url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&origin=OTHER&q=guided&start=0" % (company_id)
    headers = {'Csrf-Token':'ajax:0397788525211216808', 'X-RestLi-Protocol-Version':'2.0.0'}
    cookies['JSESSIONID'] = 'ajax:0397788525211216808'
    r = requests.get(url, cookies=cookies, headers=headers)
    content = json.loads(r.text)
    data_total = content['elements'][0]['total']

    # Calculate pages off final results at 40 results/page
    pages = math.ceil(data_total / 40)
    if pages == 0:
        pages = 1
    if data_total % 40 == 0:
        # Because we count 0... Subtract a page if there are no left over results on the last page
        pages = pages - 1
    if pages == 0:
        if mswitch.verbose is True:
            ASM.cprint("info","  [i] No employees for"  + company_name + " " + company_id,1)
        return

    print(Fore.WHITE+"  ["+Fore.GREEN + Style.BRIGHT + "!" + Style.RESET_ALL + Fore.WHITE + "] " + Fore.YELLOW + str(data_total) + " Employees Found")
    if data_total > 1000:
        pages = 25
        #print("[*] LinkedIn is capped to allow 1000 employees. More may be manually enumerated.")
    if mswitch.verbose is True:
        ASM.cprint("info","  [i] Fetching %s Pages" % str(pages),1)

    for p in range(pages):
        url = "https://www.linkedin.com/voyager/api/search/cluster?count=40&guides=List(v->PEOPLE,facetCurrentCompany->%s)&origin=OTHER&q=guided&start=%i" % (company_id, p*40)
        r = requests.get(url, cookies=cookies, headers=headers)
        content = r.text.encode('UTF-8')
        content = json.loads(content)

        if mswitch.verbose is True:
            sys.stdout.write("\r[i] Fetching page %i/%i with %i results..." % ((p),pages,len(content['elements'][0]['elements'])))
            sys.stdout.flush()
        # code to get users, for each user with a picture create a person
        for c in content['elements'][0]['elements']:
            if 'com.linkedin.voyager.search.SearchProfile' in c['hitInfo'] and c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['headless'] == False:
                try:
                    # Profile pic Link, LinkedIn profile Link and  Full Name
                    first_name = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['firstName']
                    first_name = trans(first_name)
                    first_name = first_name.lower()
                    last_name = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['lastName']
                    last_name = trans(last_name)
                    last_name = last_name.lower()

                    # Around 30% of people keep putting Certs in last name, so strip these out.
                    last_name = last_name.split(' ',1)[0]
                    full_name = first_name + " " + last_name

                    #rooturl = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['rootUrl']
                    #artifact = c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['picture']['com.linkedin.common.VectorImage']['artifacts'][3]['fileIdentifyingUrlPathSegment']
                    #person_image = rooturl + artifact
                    #person_image = trans(person_image)

                    linkedin = "https://www.linkedin.com/in/%s" % c['hitInfo']['com.linkedin.voyager.search.SearchProfile']['miniProfile']['publicIdentifier']
                    linkedin = trans(linkedin)
                    hostx.employees.append((first_name, last_name, full_name, linkedin))
                    email_syntax = hostx.pattern.replace("{f}",first_name[0]).replace("{first}",first_name).replace("{l}",last_name[0]).replace("{last}",last_name)
                    user_email = email_syntax+"@"+hostx.primary_domain

                    if checkers.is_email(user_email) and (user_email not in hostx.guessed_emails):
                        hostx.guessed_emails.append(user_email)

                except Exception as e:
                    # This triggers when a profile doesn't have an image associated with it
                    continue
    print("\n")
    return 0
