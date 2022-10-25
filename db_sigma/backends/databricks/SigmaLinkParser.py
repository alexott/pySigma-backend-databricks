import requests
from bs4 import BeautifulSoup
from .SigmaRule import *
import urllib.request
import re


def parse_sigma_directory(directory):
    parser = 'html.parser'
    resp = urllib.request.urlopen(directory)
    soup = BeautifulSoup(resp, parser, from_encoding=resp.info().get_param('charset'))

    sigma_rules = []
    for link in soup.find_all('a', href=True):
        if re.search("/SigmaHQ/sigma/blob/master/rules", link['href']) is not None:
            try:
                link = f"https://raw.githubusercontent.com{link['href'].replace('/blob', '')}"
                rule = SigmaRule(requests.get(link).text)
                sigma_rules.append(rule)
            except Exception as e:
                print(f"Bad rule: {link}")
                print(e)

    return sigma_rules
