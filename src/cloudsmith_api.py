import requests

class CloudSmithAPI:
    BASE_URL = "https://api.cloudsmith.io/v1"
    
    def __init__(self, api_key: str):
        self.api_key = api_key
    
    def auth_header(self) -> dict:
        return {"Authorization": f"Token {self.api_key}"}
    
    def query_packages(self, owner: str, repo: str) -> dict:
        url = f"{self.BASE_URL}/packages/{owner}/{repo}/"
        response = requests.get(url, headers=self.auth_header())
        return response.json()
    
    def query_scan(self, owner: str, repo: str, package: str) -> dict:
        url = f"{self.BASE_URL}/packages/{owner}/{repo}/{package}/scan/"
        response = requests.get(url, headers=self.auth_header())
        return response.json()
    
    def query_package(self, owner: str, repo: str, package: str) -> dict:
        url = f"{self.BASE_URL}/packages/{owner}/{repo}/{package}/"
        response = requests.get(url, headers=self.auth_header())
        return response.json()
    
    def get_vulnerability_info(self, owner: str, repo: str) -> dict:
        packages = self.query_packages(owner, repo)
        vulnerability_info = {}
        for package in packages:
            scan_info = self.query_scan(owner, repo, package["name"])
            vulnerability_info[package["name"]] = scan_info
        return vulnerability_info
    
    def get_owner_repos(self, owner: str) -> dict:
        url = f"{self.BASE_URL}/repositories/{owner}/"
        response = requests.get(url, headers=self.auth_header())
        return response.json()