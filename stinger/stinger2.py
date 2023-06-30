import requests
import json

BASE_URL = "https://api.cloudsmith.io/v1"
API_KEY = "cf48cdbf6d70dcd26df982bfc6a46fe3f953787d"
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

def find_vulnerabilities(records):
    critical_or_high = []
    # Check if there are any critical or high vulnerabilities
    for record in records:
        vulnerabilities = record.get('vulnerability_scan_results', [])

        for vulnerability in vulnerabilities:
            severity = vulnerability.get('severity')
            if severity in ['critical', 'high']:
                critical_or_high.append({
                    "package": record['name'],
                    "repository": record['repository'],
                    "severity": severity,
                    "vulnerability": vulnerability
                })
    return critical_or_high

def main():
    output = {}
    for repo in REPOS:
        records = get_owner_repos(OWNER, repo)
        output[repo] = records
        crit_high_vulns = find_vulnerabilities(records)
        output[repo + "-crit-high-vulns"] = crit_high_vulns  # add critical and high vulnerabilities to the output
        json.dump(
            output,
            open(f"{OWNER}-{repo}-vulnerability-stinger2-scans.json", "wt", encoding="utf8"),
            indent=4
        )

if __name__ == "__main__":
    main()
