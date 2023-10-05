"""
A program to check for host header vulnerabilities for the supplied URLs.

Needs to be designed to be easily integratable with a web scanner running other checks

Input is assumed to be valid, input validation will be implemented in the complete
"""

import sys
import requests
import re


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

def scanPage(url, proxy=None):

    # Validate URL(s)
    #print(validateURL(urls))
    
    """
    PAYLOADS

    - Arbitrary Domain (Host: rafi.hermann)
    - Stripping away from subdomain
        If stripped subdomain becomes valid, try adding a new subdomain (Host: rafi.vulnerable.site)
    - Only host/domain name is validated, not port. may allow for non-numeric port (Host: vulnerable.site:rafi)
    - Duplicate host headers (Host: vulnerable.site, Host: rafi.herm)
    - Absolute URL (GET https://vulnerable.site/ HTTP/1.1, Host: rafi.herm)
    - Line wrapping - duplicate headers where the first is indented by a space or tab
    - Host: localhost, 127.0.0.1

    Need to check for either a reflection of the hostname or a significant change in response (size, code, time etc)
    """
    

urls = sys.argv[1]
print(urls)
scanHost(urls)