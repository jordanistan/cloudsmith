import requests
import json

OWNER = ""
REPO = ""
PACKAGE = ""
API_KEY = ""
BASE_URL = "https://api.cloudsmith.io/v1"


def auth_header():
    return {"accept": "application/json",
            "X-Api-Key": API_KEY}

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


def main():
    records = get_vulnerability_info(OWNER, REPO, PACKAGE)
    json.dump(
        records,
        open(f"{OWNER}-{REPO}-{PACKAGE}-_scans.json", "wt", encoding="utf8"),
        indent=4
    )

if __name__ == "__main__":
    main()
