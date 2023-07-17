import requests
import json
import os

BASE_URL = "https://api.cloudsmith.io/v1"
API_KEY = "cf48cdbf6d70dcd26df982bfc6a46fe3f953787d"
OWNER = "cloudsmith"
REPOS = ["actions", "examples", "testing-public"]

# k = key, v = value, d = dictionary
def flatten_dict(d, separator='_', prefix=''):
    items = []
    for k, v in d.items():
        new_key = prefix + separator + k if prefix else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, separator, new_key).items())
        elif isinstance(v, list):
            for i, elem in enumerate(v):
                if isinstance(elem, dict):
                    items.extend(flatten_dict(elem, separator, new_key + separator + str(i)).items())
                else:
                    items.append((new_key + separator + str(i), elem))
        else:
            items.append((new_key, v))
    return dict(items)


def process_json_file(file_name, keys_to_extract):
    # Open the file as JSON and store it in a dictionary called data.
    with open(file_name, 'r') as file:
        data = json.load(file)

    # Flatten the JSON and store it in a list
    flat_dicts = [flatten_dict(item) for item in data['actions']]

    # Return the flattened dictionaries that contain the keys we want to extract from the JSON file.
    return flat_dicts

def write_flat_dicts_to_json(file_name, flat_dicts):
    # Open the file in write mode and store it in a variable called file. 
    with open(file_name, 'w') as file:
        # Write the flat_dicts list to the file as JSON with indentation of 4. 
        json.dump(flat_dicts, file, indent=4)

def auth_header():
    return {"accept": "application/json",
            "X-Api-Key": API_KEY}

def query_packages(owner, repo):
    # Query the packages endpoint for the owner and repo specified. 
    url = f"{BASE_URL}/packages/{owner}/{repo}/"
    response = requests.get(url, headers=auth_header())
    return response.json()

def query_scan(owner, repo, package, identifier):
    # Query the vulnerabilities endpoint for the owner, repo, package, and identifier specified. 
    url = f"{BASE_URL}/vulnerabilities/{owner}/{repo}/{package}/{identifier}/"
    response = requests.get(url, headers=auth_header())
    return response.json()

def query_package(owner, repo, package):
    # Query the vulnerabilities endpoint for the owner, repo, and package specified.
    url = f"{BASE_URL}/vulnerabilities/{owner}/{repo}/{package}/"
    response = requests.get(url, headers=auth_header())
    return response.json()


def get_vulnerability_info(owner, repo, package):
    # Get the vulnerability information for the owner, repo, and package specified. 
    records = []
    for scan in query_package(owner, repo, package):
        assert package == scan["package"]["identifier"]
        ident = scan["identifier"]
        results = query_scan(owner, repo, package, ident)
        scan["scan"] = results["scan"]
        records.append(scan)
    return records

def get_owner_repos(owner, repo):
    # Get the owner and repo specified.
    output = []
    for record in query_packages(OWNER, repo):
        package_id = record["identifier_perm"]
        scans = get_vulnerability_info(owner, repo, package_id)
        record["vulnerability_scan_results"] = scans
        output.append(record)
    return output

def find_vulnerabilities(records):
    # Check if there are any critical or high vulnerabilities in the records. 
    for record in records:
        vulnerabilities = record.get('vulnerability_scan_results', [])

        for vulnerability in vulnerabilities:
            # Get the severity of the vulnerability.  Can be critical, high, medium, low, or unknown. but this is likely to change and be filted out via splunk
            severity = vulnerability.get('severity')
            if severity in ['critical', 'high']:
                print(f"Package {record['name']} in repo {record['repository']} has a {severity} vulnerability.")

def main():
    output = {}

    # Example usage the keys_to_extract and what to filter on. 
    keys_to_extract = ['self_url', 'stage', 'stage_str', 'stage_updated_at', 'status', 'status_reason',
                    'status_str', 'status_updated_at', 'is_sync_awaiting', 'is_sync_completed', 
                    'is_sync_failed', 'is_sync_in_flight', 'is_sync_in_progress', 'is_downloadable', 
                    'is_quarantined', 'sync_finished_at', 'sync_progress', 'architectures_0_name', 
                    'architectures_0_description', 'checksum_md5', 'checksum_sha1', 'checksum_sha256', 
                    'checksum_sha512', 'dependencies_checksum_md5', 'dependencies_url', 'description', 
                    'distro', 'distro_version', 'downloads', 'cdn_url', 'epoch', 'extension', 'filename', 
                    'files_0_checksum_md5', 'files_0_checksum_sha1', 'files_0_checksum_sha256', 
                    'files_0_checksum_sha512', 'files_0_cdn_url', 'files_0_downloads', 'files_0_filename', 
                    'files_0_is_downloadable', 'files_0_is_primary', 'files_0_is_synchronised', 
                    'files_0_signature_url', 'files_0_size', 'files_0_slug_perm', 'files_0_tag', 
                    'format', 'format_url', 'identifier_perm', 'indexed', 'license', 'name', 
                    'namespace', 'namespace_url', 'num_files', 'package_type', 'release', 
                    'repository', 'repository_url', 'security_scan_status', 
                    'security_scan_status_updated_at', 'security_scan_started_at', 
                    'security_scan_completed_at', 'self_html_url', 'status_url', 'signature_url', 
                    'size', 'slug', 'slug_perm', 'subtype', 'summary', 'tags_version_0', 'type_display', 
                    'uploaded_at', 'uploader', 'uploader_url', 'version', 'version_orig', 
                    'vulnerability_scan_results_url', 'vulnerability_scan_results_0_identifier', 
                    'vulnerability_scan_results_0_created_at', 'vulnerability_scan_results_0_package_identifier', 
                    'vulnerability_scan_results_0_package_name', 'vulnerability_scan_results_0_package_version', 
                    'vulnerability_scan_results_0_package_url', 'vulnerability_scan_results_0_scan_id', 
                    'vulnerability_scan_results_0_has_vulnerabilities', 'vulnerability_scan_results_0_num_vulnerabilities', 
                    'vulnerability_scan_results_0_max_severity', 'vulnerability_scan_results_0_scan_target', 
                    'vulnerability_scan_results_0_scan_type']

    for repo in REPOS:
        # Get the owner and repo specified. 
        records = get_owner_repos(OWNER, repo)
        output[repo] = records
        find_vulnerabilities(records)  # use the function to find vulnerabilities in the records.
        json.dump(
            output,
            open(f"{OWNER}-{repo}-vulnerability-stinger-scans.json", "wt", encoding="utf8"), # write the output to a json file to see results locally.
            indent=4
        )
# flatten the json file to make it easier to read in splunk.
        flatten_dict = process_json_file(f"{OWNER}-{repo}-vulnerability-stinger-scans.json", keys_to_extract)
        os.remove(f"{OWNER}-{repo}-vulnerability-stinger-scans.json")
        write_flat_dicts_to_json(f"{OWNER}-{repo}-vulnerability-stinger-scans.json", flatten_dict)

    
if __name__ == "__main__":
    main()
 