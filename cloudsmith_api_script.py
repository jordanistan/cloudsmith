import requests
import json
import time
import socket
from splunk_http_event_collector import http_event_collector
from datetime import datetime


BASE_URL = "https://api.cloudsmith.io/v1"
API_KEY = "redacted"


# Setup logging to Splunk
SPLUNK_SERVER = "server"
SPLUNK_SERVER_PORT = "port"
SPLUNK_HEC_TOKEN = "token"



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

class http_event_collector:
    
    def __init__(self, token, server, http_event_port="8088", input_type="json", host="", http_event_server_ssl=False):
        self.token = token
        self.server = server
        self.port = http_event_port
        self.input_type = input_type
        if host:
            self.host = host
        else:
            self.host = socket.gethostname()
        self.scheme = "http" if not http_event_server_ssl else "https"
        
    def get_auth(self):
        return {"Authorization": f"Splunk {self.token}"}
    
    def get_uri(self):
        return f"{self.scheme}://{self.server}:{self.port}/services/collector/event"
    
    def send_event(self, data):
        payload = {"event": data}
        uri = self.get_uri()
        auth = self.get_auth()
        resp = requests.post(uri, json=payload, headers=auth)
        print(resp)
        return resp

def FOR_SENDING_DATA_TO_SPLUNK():
    host = socket.gethostname()
    splunk_event = http_event_collector(
        SPLUNK_HEC_TOKEN, 
        SPLUNK_SERVER, 
        http_event_port=SPLUNK_SERVER_PORT, 
        input_type="json", 
        http_event_server_ssl=False, 
        host=host
    )
    for repo in REPOS:
        records = get_owner_repos(OWNER, repo)
        payload = {repo: records}
        resp = splunk_event.send_event(payload)
        print(resp)
        
    
if __name__ == "__main__":
    FOR_SENDING_DATA_TO_SPLUNK()
