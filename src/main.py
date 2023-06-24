import json
from cloudsmith_api import CloudSmithAPI

API_KEY = "your_api_key_here"
OWNER = "your_owner_here"
REPOS = ["your_repo_here"]

def main():
    api = CloudSmithAPI(API_KEY)
    vulnerability_info = {}
    for repo in REPOS:
        packages = api.get_vulnerability_info(OWNER, repo)
        vulnerability_info[repo] = packages
    with open("vulnerability_info.json", "w") as f:
        json.dump(vulnerability_info, f)

if __name__ == "__main__":
    main()