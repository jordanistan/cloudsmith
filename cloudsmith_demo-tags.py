import requests
import json
import time
from datetime import datetime

BASE_URL = "https://api.cloudsmith.io/v1"
API_KEY = "cf48cdbf6d70dcd26df982bfc6a46fe3f953787d"


# Setup logging to Splunk
SPLUNK_SERVER = "http-inputs.acme.splunkcloud.com"
SPLUNK_SERVER_PORT = "8088"
SPLUNK_HEC_TOKEN = "REPLACE_ME"


OWNER = "cloudsmith"
REPOS = ["actions", "examples", "testing-public"]


def auth_header():
    return {"accept": "application/json",
            "X-Api-Key": API_KEY}


def query_packages(owner, repo):
    url = f"{BASE_URL}/packages/{owner}/{repo}/"
    response = requests.get(url, headers=auth_header())
    return response.json()


def query_scan(owner, repo, package, identifier):
    url = f"{BASE_URL}/vulnerabilities/{owner}/{repo}/{package}/{identifier}/"
    response = requests.get(url, headers=auth_header())
    return response.json()


def query_package(owner, repo, package):
    url = f"{BASE_URL}/vulnerabilities/{owner}/{repo}/{package}/"
    response = requests.get(url, headers=auth_header())
    return response.json()



def get_vulnerability_info(owner, repo, package):
    records = []
    for scan in query_package(owner, repo, package):
        assert package == scan["package"]["identifier"]
        ident = scan["identifier"]
        results = query_scan(owner, repo, package, ident)
        scan["scan"] = results["scan"]
        records.append(scan)
    return records


def get_owner_repos(owner, repo):
    output = []
    for record in query_packages(OWNER, repo):
        package_id = record["identifier_perm"]
        scans = get_vulnerability_info(owner, repo, package_id)
        record["vulnerability_scan_results"] = scans
        output.append(record)
    return output


def FOR_WRITING_DATA_TO_JSON_FILE():
    output = {}
    for repo in REPOS:
        records = get_owner_repos(OWNER, repo)
        output[repo] = records
        json.dump(
            output,
            open(f"{OWNER}-{repo}-vulnerability-scans.json", "wt", encoding="utf8"),
            indent=4
        )



class HttpEventCollector:

    def __init__(
            self,
            token,
            http_event_server,
            host="",
            port='8088'):
        self.token = token
        self.currentByteLength = 0
        self.input_type = "json"
        self.includeTime = True 
        self.host = host
        protocol = 'http'
        input_url = '/event'
        self.server_uri = '%s://%s:%s/services/collector%s' % (protocol, http_event_server, port, input_url)
        
    def send_event(self, payload, meta=None):
        headers = {'Authorization':'Splunk '+self.token}
        if self.input_type == 'json':
            if 'host' not in payload:
                payload.update({"host":self.host})
            if self.includeTime and not eventtime and 'time' not in payload:
                timeOffsetForEmbeddedEpoch = 946684800 
                eventtime = str(int(time.time()+timeOffsetForEmbeddedEpoch))
                payload.update({"time":eventtime})
        if meta:
            payload.update(meta)
        event = []
        if self.input_type == 'json':
            event.append(json.dumps(payload))
        r = requests.post(self.server_uri, data=event[0], headers=headers)
        print(r.text)


def FOR_SENDING_DATA_TO_SPLUNK():
    splunk = HttpEventCollector(SPLUNK_HEC_TOKEN, SPLUNK_SERVER, port=SPLUNK_SERVER_PORT)
    for repo in REPOS:
        records = get_owner_repos(OWNER, repo)
        payload = {repo: records}
        meta = {"sourcetype": "cloudsmith:vuln-appsec", 
                "index": "vuln-appsec", 
                "time": datetime.timestamp(datetime.today())}
        splunk.send_event(payload, meta=meta)

if __name__ == "__main__":
    FOR_SENDING_DATA_TO_SPLUNK()
