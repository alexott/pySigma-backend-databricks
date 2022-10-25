import requests
from bs4 import BeautifulSoup
from .SigmaRule import *
import urllib.request
import re


def parse_sigma_link(link):
    parser = 'html.parser'
    resp = urllib.request.urlopen(link)
    soup = BeautifulSoup(resp, parser, from_encoding=resp.info().get_param('charset'))

    sigma_rules = []
    if re.search("github\\.com/SigmaHQ/sigma/blob/master/rules/*/*/*", link) is not None:
        sigma_rules.append(
            SigmaRule(requests.get(link.replace('/blob', '').replace('github', 'raw.githubusercontent')).text)
        )
    elif re.search("github\\.com/SigmaHQ/sigma/tree/master/rules/*/*", link) is not None:
        for x in soup.find_all('a', href=True):
            if re.search("/SigmaHQ/sigma/blob/master/rules", x['href']) is not None:
                try:
                    x = f"https://raw.githubusercontent.com{x['href'].replace('/blob', '')}"
                    rule = SigmaRule(requests.get(x).text)
                    sigma_rules.append(rule)
                except Exception as e:
                    print(f"Bad rule: {x}")
                    print(e)
    elif re.search("raw\\.githubusercontent\\.com/SigmaHQ/sigma/master/rules/*/*/*", link) is not None:
        sigma_rules.append(SigmaRule(requests.get(link).text))

    return sigma_rules
