import gzip
import json
from datetime import date
import requests

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.gz"
SCRIPT_FILE = __file__
DATA_FILE = '../data/'+SCRIPT_FILE.split('.')[0]+'.txt'

file = open(DATA_FILE, 'w')

class NVDDataSource:
    def updated_advisories(self):
        current_year = date.today().year
        for year in range(2002, current_year + 1):
            download_url = BASE_URL.format(year)
            data = self.fetch(download_url)
            self.to_advisories(data)

    @staticmethod
    def fetch(url):
        gz_file = requests.get(url)
        data = gzip.decompress(gz_file.content)
        return json.loads(data)

    def to_advisories(self, nvd_data):
        for cve_item in nvd_data["CVE_Items"]:
            if self.related_to_hardware(cve_item):
                continue

            summaries = [desc["value"] for desc in cve_item["cve"]["description"]["description_data"]]
            summary = max(summaries, key=len)
            file.write(summary + '@')

    def related_to_hardware(self, cve_item):
        for cpe in self.extract_cpes(cve_item):
            cpe_comps = cpe.split(":")
            if cpe_comps[2] == "h":
                return True
        return False

    @staticmethod
    def extract_cpes(cve_item):
        cpes = set()
        for node in cve_item["configurations"]["nodes"]:
            for cpe_data in node.get("cpe_match", []):
                cpes.add(cpe_data["cpe23Uri"])
        return cpes

NVDDataSource().updated_advisories()

file.close()