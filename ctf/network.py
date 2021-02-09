import requests
from bs4 import BeautifulSoup, SoupStrainer


def all_links(url):
    response = requests.get(url)

    rel = []
    for link in BeautifulSoup(response.text, parse_only=SoupStrainer('a'), features="lxml"):
        if hasattr(link, 'href'):
            try:
                rel.append(link['href'])
            except KeyError:
                pass

    return rel
