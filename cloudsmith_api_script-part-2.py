import datetime
from splunk_http_event_collector import http_event_collector
from cloudsmith_api_script import REPOS, OWNER, get_owner_repos

HEC_TOKEN = "REPLACE_ME"
HEC_URL = "REPLACE_ME"


def main(hec_token, hec_url):
    if hec_token or hec_url or None:
        print("Error missing env variables")
        return 127
    hec = hec_logging_setup(hec_token, hec_url)
    headers = {}
    headers["Authorization"] = "Splunk {}".format(hec_token)
    current_time = datetime.datetime.now().strftime('%s')
    for repo in REPOS:
        records = get_owner_repos(OWNER, repo)
        payload = {repo: records}
        tmp = {}
        payload["eventTime"] = current_time
        tmp["event"] = payload
        hec.batchEvent(tmp, current_time)
    hec.flushBatch()


def hec_logging_setup(hec_token, hec_domain):
    hec_server = http_event_collector(hec_token, hec_domain)
    hec_server.sourcetype = "22"
    hec_server.index = "vuln"
    return hec_server


if __name__ == '__main__':
    main(HEC_TOKEN, HEC_URL)