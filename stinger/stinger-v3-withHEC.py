import requests
import json
from splunk_http_event_collector import http_event_collector

def printToJSON(data, file):
    json.dump(
        data,
        open(f"{file}", "wt", encoding="utf8"),
        indent=4
    )

class Constants:
    """ Constants that shouldn't be touched unless you know what you're doing
    """
    BASE_URL = "https://api.cloudsmith.io/v1"

class Fields:
    """ Field IDs to use from the returned JSON data
    """
    PACKAGE_ID = "identifier_perm"
    PACKAGE_NAME = "name"
    PACKAGE_UPLOADER = "uploader"
    PACKAGE_QUARANTINE_FIELD = "is_quarantined"
    PACKAGE_TAGS = "tags"
    PACKAGE_VULNERABILITY = "vulnerability_info"
    SEVERITY = "severity"
    SCAN_STATUS = "security_scan_status"
    SCAN_COMPLETED_TIME = "security_scan_completed_at"
    SCAN_MAX_SEVERITY = "max_severity"
    SCAN_HAS_VULNERABILITIES = "max_severity"

class Settings:
    """ All modifiable settings that can be altered by the user
    """
    API_KEY = "cf48cdbf6d70dcd26df982bfc6a46fe3f953787d"
    OWNER = "cloudsmith"
    SEVERITIES = ["Critical", "High"] # severities to filter for
    SPLUNK_TOKEN = ""
    SPLUNK_SERVER = ""
    SPLUNK_EVENT_NAME = "vulnerabilities_update"
    # source and sourcetype will get overridden if you mention here
    # if you wish to keep the token's default source & sourcetype as defined in the
    #  token's settings in Splunk, comment out the lines where these 2 are assigned
    #  to the payload.
    #  https://docs.splunk.com/Documentation/SplunkCloud/9.0.2303/Data/UseHECusingconffiles
    SPLUNK_SOURCE = "cloudsmith"  # name of the source of event to be told to Splunk
    SPLUNK_SOURCETYPE = "api/json" # source type defined by the Splunk token

class CloudSmithQuery:
    """ Class that represents all data that can be queries from CloudSmith
    """
    def __init__(self, api_key, owner, severities):
        self.api_key = api_key
        self.owner = owner
        self.severities = severities

    def _auth_header(self):
        return {"accept": "application/json",
                "X-Api-Key": self.api_key}

    def get_all_packages(self, repo):
        url = f"{Constants.BASE_URL}/packages/{self.owner}/{repo}/"
        response = requests.get(url, headers=self._auth_header())
        return response.json()

    def _get_package_vulnerabilities(self, repo, package):
        package_id = package[Fields.PACKAGE_ID]
        url = f"{Constants.BASE_URL}/vulnerabilities/{self.owner}/{repo}/{package_id}/"
        response = requests.get(url, headers=self._auth_header())
        return response.json()

    def _get_scan_data(self, repo, package, scan_id):
        package_id = package[Fields.PACKAGE_ID]
        url = f"{Constants.BASE_URL}/vulnerabilities/{self.owner}/{repo}/{package_id}/{scan_id}/"
        response = requests.get(url, headers=self._auth_header())
        return response.json()

    def get_vulnerability_info(self, repo, package):
        """ get all vulnerability info for this package & attach it to the package's info"""
        # make a copy of the package object so that we can add the vulnerability data
        # without modifying any of the package object itself
        package_with_vulnerability_info = package
        scans = []
        for scan in self._get_package_vulnerabilities(repo, package):
            assert package[Fields.PACKAGE_ID] == scan["package"]["identifier"] # sanity check
            scan_id = scan["identifier"]
            results = self._get_scan_data(repo, package, scan_id)
            scans.append(results)

        package[Fields.PACKAGE_VULNERABILITY] = scans
        return package_with_vulnerability_info

    def matches_severity(self, package):
        """ Check if there are any packages with vulnerabilities matching the expected ones
            This function is designed to return True/False so that it could be passed to
            python's filter() function easily

            defaults expected severities to Critical & High, but is customizable
        """
        vulnerabilities = package.get(Fields.PACKAGE_VULNERABILITY, [])

        for vulnerability in vulnerabilities:
            if not vulnerability.get(Fields.SCAN_HAS_VULNERABILITIES):
                # if this scan result shows no vulnerabilities then
                #  just continue and look at the next result
                continue

            severity = vulnerability.get(Fields.SCAN_MAX_SEVERITY)
            if severity.lower() in [s.lower() for s in self.severities]: # case insensitive match
                # if any scan result suggested a matching severity 
                return True
        # if none of the scan results matched expected severities
        return False

class SplunkDataExtractor:
    FIELDS = [
            Fields.SCAN_STATUS,
            Fields.SCAN_COMPLETED_TIME,
            Fields.PACKAGE_UPLOADER,
            Fields.PACKAGE_QUARANTINE_FIELD,
            Fields.PACKAGE_NAME,
            Fields.PACKAGE_TAGS
            ]
    def extract_splunk_fields(self, package):
        extracted_data = {}
        for f in SplunkDataExtractor.FIELDS:
            extracted_data[f] = package[f]

        return extracted_data

def main():
    SEVERITIES = ["Critical", "High"]
    cs_query = CloudSmithQuery(Settings.API_KEY, Settings.OWNER, SEVERITIES)
    splunk_extractor = SplunkDataExtractor()
    splunk_hec = http_event_collector(Settings.SPLUNK_TOKEN, Settings.SPLUNK_SERVER)
    # REPOS = ["actions", "examples", "testing-public"]
    REPOS = ["examples"]
    for repo in REPOS:
        # fetch all packages for this repo
        all_packages = cs_query.get_all_packages(repo)
        # get all vulnerability data for each package
        package_vulnerabilities = [cs_query.get_vulnerability_info(repo, package) for package in all_packages]
        # filter vulnerability data for each package
        filtered_vulnerabilities = filter(cs_query.matches_severity, package_vulnerabilities)
        # printToJSON(list(filtered_vulnerabilities), f"vulnerabilities-{repo}.json")

        # extract the parts that are needed by Splunk
        splunk_data = [splunk_extractor.extract_splunk_fields(p) for p in filtered_vulnerabilities]
        # printToJSON(splunk_data, f"splunkdata-{repo}.json")

        # send an event to Splunk for this repo
        # as per: https://docs.splunk.com/Documentation/SplunkCloud/9.0.2303/Data/HTTPEventCollectortokenmanagement
        splunk_payload = {}
        splunk_payload["event"] = Settings.SPLUNK_EVENT_NAME
        splunk_payload["source"] = Settings.SPLUNK_SOURCE
        splunk_payload["sourcetype"] = Settings.SPLUNK_SOURCETYPE
        splunk_payload["fields"] = splunk_data
        # append repo name as 1 of the fields
        splunk_payload["fields"]["repo"] = repo
        splunk_hec.batchEvent(splunk_payload)

    # flush the batch at the end, so that events for all repos are sent to Splunk in 1 go
    splunk_hec.flushBatch()
        

if __name__ == "__main__":
    main()
