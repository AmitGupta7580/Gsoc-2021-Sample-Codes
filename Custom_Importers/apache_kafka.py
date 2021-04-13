import requests
import tqdm
from bs4 import BeautifulSoup

GH_PAGE_URL = "https://raw.githubusercontent.com/apache/kafka-site/asf-site/cve-list.html"
SCRIPT_FILE = __file__
DATA_FILE = '../data/'+SCRIPT_FILE.split('.')[0]+'.txt'

file = open(DATA_FILE, 'w')

class ApacheKafkaDataSource:
    @staticmethod
    def fetch_advisory_page():
        page = requests.get(GH_PAGE_URL)
        return page.content

    def updated_advisories(self):
        advisory_page = self.fetch_advisory_page()
        self.to_advisory(advisory_page)

    def to_advisory(self, advisory_page):
        advisory_page = BeautifulSoup(advisory_page, features="lxml")
        cve_section_beginnings = advisory_page.find_all("h2")
        print(len(cve_section_beginnings))
        for cve_section_beginning in cve_section_beginnings:
            summary = cve_section_beginning.find_next_sibling("p").text
            file.write(summary + '@')

ApacheKafkaDataSource().updated_advisories()

file.close()