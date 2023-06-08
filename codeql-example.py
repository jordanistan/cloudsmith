import requests
import datetime
import re
from collections.abc import MutableMapping
from contextlib import suppress
import os
from splunk_http_event_collector import http_event_collector


def main(event, context):

    current_time = datetime.datetime.now().strftime('%s')
    all_results = []
    secrets = []
    hec_token = os.getenv("hec_token")
    hec_url = os.getenv("hec_url")
    gh_token = os.getenv("gh_token")

    if hec_token or hec_url or gh_token is None:
        print("Error missing env variables")
        return 127

    hec = hec_logging_setup(hec_token, hec_url)

    headers = {}
    headers["Authorization"] = "Bearer {}".format(gh_token)
    headers["X-GitHub-Api-Version"] = "2022-11-28"
    headers["Accept"] = "application/vnd.github+json"

    commure_alerts = collect_scanning_alerts("commure", headers)
    pk_alerts = collect_scanning_alerts("hcapatientkeeper", headers)

    all_results.extend(commure_alerts)
    all_results.extend(pk_alerts)
    print("Total Findings: {}".format(len(all_results)))

    # Process CodeQL Data
    for result in all_results:
        tmp = {}
        result["eventTime"] = current_time

        # Removing noisy URL keys from data
        delete_keys_from_dict(result)

        tmp["event"] = result
        hec.batchEvent(tmp, current_time)

    hec.flushBatch()

    # Change sourcetype for new data
    hec.sourcetype = "github:secrets"
    current_time = datetime.datetime.now().strftime('%s')

    # Collect found secrets
    secrets = collect_secrets_info(headers)

    # Process found secret data
    for secret in secrets:
        # Remove the actual secret
        secret.pop("secret", None)

        # Add an eventTime for Splunk parsing purposes
        secret["eventTime"] = current_time

        # Let's remove all the "url" keys, it just pointless data no one wants or needs
        delete_keys_from_dict(secret)

        tmp = {}
        tmp["event"] = secret
        hec.batchEvent(tmp, current_time)

    hec.flushBatch()

    # Set things up for dependabot collection
    hec.sourcetype = "dependabot"
    current_time = datetime.datetime.now().strftime('%s')

    dependabot = collect_dependabot(headers)

    # Process dependabot data
    for vuln in dependabot:
        # Add an eventTime for Splunk parsing purposes
        vuln["eventTime"] = current_time

        # Unnecessary data
        vuln["security_advisory"].pop("references", None)
        vuln["security_advisory"].pop("description", None)

        delete_keys_from_dict(vuln)
        tmp = {}
        tmp["event"] = vuln
        hec.batchEvent(tmp, current_time)


def collect_scanning_alerts(org, headers):

    results = []
    link_regex = re.compile('(?<=<)([\\S]*)(?=>; rel="Next")', re.IGNORECASE)

    r = requests.get("https://api.github.com/orgs/{}/code-scanning/alerts?per_page=100".format(org), headers=headers)

    if r.status_code == 200:
        results.extend(r.json())
    else:
        print("Error with scanning alerts: {}".format(r.status_code))
        return None

    while link_regex.search(r.headers['link']) is not None:
        # print("Org: {} Next Link: {} # Results: {}".format(org, link_regex.search(r.headers['link']).group(), len(results)))

        # Extract next link from headers using regex
        url = link_regex.search(r.headers['link']).group()
        r = requests.get(url, headers=headers)

        # We should exit the loop if we aren't successful
        if r.status_code != 200:
            print("Non-200 status code")
            break

        results.extend(r.json())

    return results


def collect_secrets_info(headers):
    url = "https://api.github.com/enterprises/commure/secret-scanning/alerts?state=open&per_page=100"
    data_to_return = []

    link_regex = re.compile('(?<=<)([\\S]*)(?=>; rel="Next")', re.IGNORECASE)

    r = requests.get(url, headers=headers)

    # We should exit the loop if we aren't successful
    if r.status_code == 200:
        data_to_return.extend(r.json())
    else:
        print("Error with secret alerts: {}".format(r.status_code))
        return None

    if "link" in r.headers:
        while link_regex.search(r.headers['link']) is not None:
            # Search for next URL in headers
            url = link_regex.search(r.headers['link']).group()

            r = requests.get(url, headers=headers)

            # We should exit the loop if we aren't successful
            if r.status_code != 200:
                print("Non-200 status code")
                break

            data_to_return.extend(r.json())
    # else:
        # print("Missing link header. Status Code: {}".format(r.status_code))
        # print("Headers: {}".format(r.headers))

    return data_to_return


def collect_dependabot(headers):
    results = []
    link_regex = re.compile('(?<=<)([\\S]*)(?=>; rel="Next")', re.IGNORECASE)

    r = requests.get("https://api.github.com/enterprises/commure/dependabot/alerts?state=open&per_page=100", headers=headers)

    if r.status_code == 200:
        results.extend(r.json())
    else:
        print("Error with dependabot: {}".format(r.status_code))
        return None

    while link_regex.search(r.headers['link']) is not None:
        # Extract next link from headers using regex
        url = link_regex.search(r.headers['link']).group()
        r = requests.get(url, headers=headers)

        # We should exit the loop if we aren't successful
        if r.status_code != 200:
            print("Non-200 status code")
            break

        results.extend(r.json())

    return results


def delete_keys_from_dict(dictionary):
    for key in list(dictionary.keys()):
        if key.endswith("url"):
            with suppress(KeyError):
                del dictionary[key]
    for value in dictionary.values():
        if isinstance(value, MutableMapping):
            delete_keys_from_dict(value)


def hec_logging_setup(hec_token, hec_domain):
    hec_server = http_event_collector(hec_token, hec_domain)
    hec_server.sourcetype = "codeql"
    hec_server.index = "vuln"

    return hec_server


if __name__ == '__main__':
    main()