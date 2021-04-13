import requests
from typing import Any
from typing import Mapping

debian_tracker_url="https://security-tracker.debian.org/tracker/data/json"
SCRIPT_FILE = __file__
DATA_FILE = '../data/'+SCRIPT_FILE.split('.')[0]+'.txt'

file = open(DATA_FILE, 'w')

class DebianDataSource:

    def updated_advisories(self):
        for pkg_name, records in self._fetch().items():
            self._parse(pkg_name, records)

    def _fetch(self) -> Mapping[str, Any]:
        return requests.get(debian_tracker_url).json()

    def _parse(self, pkg_name: str, records: Mapping[str, Any]):
        for cve_id, record in records.items():
            summary = record.get("description", "")
            if summary == '':
                continue
            file.write(summary + '@')

DebianDataSource().updated_advisories()

file.close()