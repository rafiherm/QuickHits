"""
A program to check for host header vulnerabilities for the supplied URLs.

Needs to be designed to be easily integratable with a web scanner running other checks

Input is assumed to be valid, input validation will be implemented in the complete
"""

import sys
import httpx
import datetime
from colorama import Fore, Back, Style

def validateURL(url):
    """
    
    # INCOMPLETE

    # Helper function to ensure a supplied URL is valid for scanning
    

    Valid = False

    # Check if not a string
    if isinstance(url, str):

        # Check if string adheres to url format
        # http(s)://domain.com(:portno)/
        regex = r"^(http|https)://[^\w$].[^\w.]*(:\d+)?(/[^\s]*)?$"
        if re.match(regex, url) is not None:
            Valid = True

    """
    pass

def logEvent(icon, colour, message):
    # Prints relevant data prettily
    time = datetime.datetime.now()
    print("[" + colour + icon + Style.RESET_ALL + "] -", message, "| %s" % time)

def scanHeaderFuzz(url, proxy, hostheader):

    with httpx.Client(proxies=proxy) as client:

        headers = httpx.Headers(
            [
                # put your headers here
                #("Host", "rafi"),
                #("Host", "herm"),
                ("Cache-Control", "no-cache"),
                ("Cache-Control", "no-store")
            ]
        )

        request = client.build_request("GET", url)
        
        request.headers = headers
        r = client.send(request)
        print(r.text)
        #return httpx.get(url=url, proxies=proxy, headers=headers, follow_redirects=False)

def scanURL(url, proxy=None):

    # Validate URL(s)
    # group URLs if there are redirects
    #print(validateURL(urls))
    
    """
    CHECKS

    - Arbitrary Domain (Host: rafi.hermann)
    - new subdomain
    - Stripping away from subdomain
        If stripped subdomain becomes valid, try adding a new subdomain (Host: cybercx.vulnerable.site)
    - Only host/domain name is validated, not port. may allow for non-numeric port (Host: vulnerable.site:cybercx)

    - Host: localhost, 127.0.0.1 and other permutations
    - accessing vhosts

    CHECKS I NEED TO FIGURE OUT - requests, httpx and curl are blocking duplicate host headers

    - Duplicate host headers (Host: vulnerable.site, Host: rafi.herm)
    - Absolute URL (GET https://vulnerable.site/ HTTP/1.1, Host: rafi.herm)
    - Line wrapping - duplicate headers where the first is indented by a space or tab
    
    Need to check for either a reflection of the hostname or a significant change in response (size, code, time etc)
    """
    
    
    # CHECK 0: STANDARD APPLICATION BEHAVIOUR
    standardRequest = httpx.get(url=url, proxies=proxy, follow_redirects=False)
    #standardRequestAttr = [standardRequest.status_code, standardRequest.elapsed.total_seconds(), standardRequest.headers, len(standardRequest.content)]


    # CHECK 1: ARBITRARY HOST HEADER
    arbHeader = "cybercx.com.au"
    arbDomainResponse = scanHeaderFuzz(url, proxy, arbHeader)
    
    # check if application responds differently to new host header. if so, log it
    if arbDomainResponse.status_code != standardRequest.status_code:
        logEvent("*", Fore.BLUE, "Arbirtary host header returns status code " + str(arbDomainResponse.status_code))
    else:
        logEvent("*", Fore.BLUE, "Arbirtary host header does not change status code")
    
    # check if arbitrary host header is reflected in response header(s)
    hostInHeaders = False
    for key in arbDomainResponse.headers:
        if arbHeader in arbDomainResponse.headers[key]:
            hostInHeaders = True

    if hostInHeaders:
        logEvent("!", Fore.RED, "Arbirtary host header reflected in response header(s)") 

    # check if arbitrary host header returns a "significantly" different response body size
    #bodySize

    # check if arbitraru host header is refleced in response body
    if arbHeader in arbDomainResponse.text.lower():
        logEvent("!", Fore.RED, "Arbirtary host header reflected in response body") 

    


    

url = sys.argv[1]
proxy = sys.argv[2]
print(url)
scanURL(url, { "http://" : proxy})
