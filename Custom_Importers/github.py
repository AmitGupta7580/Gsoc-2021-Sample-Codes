import json
from typing import List
from typing import Mapping
import requests

SCRIPT_FILE = __file__
DATA_FILE = '../data/'+SCRIPT_FILE.split('.')[0]+'.txt'
gh_token = '<GITHUB_TOKEN>'
ecosystems = ["MAVEN", "NUGET", "COMPOSER", "PIP", "RUBYGEMS"]
endpoint = "https://api.github.com/graphql"
query = """
        query{
        securityVulnerabilities(first: 100, ecosystem: %s, %s) {
            edges {
            node {
                advisory {
                identifiers {
                    type
                    value
                }
                summary
                references {
                    url
                }
                severity
                }
                package {
                name
                }
                vulnerableVersionRange
            }
            }
            pageInfo {
            hasNextPage
            endCursor
            }
        }
        }
        """

file = open(DATA_FILE, 'w')

class GitHubAPIDataSource:

    def fetch(self) -> Mapping[str, List[Mapping]]:
        headers = {"Authorization": "token " + gh_token}
        api_data = {}
        for ecosystem in ecosystems:

            api_data[ecosystem] = []
            end_cursor_exp = ""

            while True:

                query_json = {"query": query % (ecosystem, end_cursor_exp)}
                resp = requests.post(endpoint, headers=headers, json=query_json).json()
                if resp.get("message") == "Bad credentials":
                    print("Invalid GitHub token")

                end_cursor = resp["data"]["securityVulnerabilities"]["pageInfo"]["endCursor"]
                end_cursor_exp = "after: {}".format('"{}"'.format(end_cursor))
                api_data[ecosystem].append(resp)

                if not resp["data"]["securityVulnerabilities"]["pageInfo"]["hasNextPage"]:
                    break
        return api_data

    def process_response(self):
        data = self.fetch()
        for ecosystem in data:
            for resp_page in data[ecosystem]:
                for adv in resp_page["data"]["securityVulnerabilities"]["edges"]:
                    summary = adv["node"]["advisory"]["summary"]
                    file.write(summary + '@')

GitHubAPIDataSource().process_response()

file.close()