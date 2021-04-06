import json
import os

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from tests.functional.services.policy_engine.conftest import FEEDS_DIR
from tests.functional.services.utils import http_utils


def find_by_name(records, name):
    for record in records:
        if record["name"] == name:
            return record

    return None


class TestFeedSync:
    def test_expected_feed_sync(self):
        feed_sync_resp = policy_engine_api.feeds.feeds_sync()

        assert feed_sync_resp == http_utils.APIResponse(200)

        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)
        assert feeds_get_resp == http_utils.APIResponse(200)

        # get feeds index file
        with open(f"{FEEDS_DIR}/index.json") as f:
            file_contents = f.read()
            expected_feeds = json.loads(file_contents)["feeds"]

        assert len(feeds_get_resp.body) == len(expected_feeds)

        for expected_feed in expected_feeds:
            # assert that expected feed is present in found list and enabled
            actual_feed = find_by_name(feeds_get_resp.body, expected_feed["name"])
            assert actual_feed
            assert actual_feed["enabled"]

            with open(
                os.path.join(FEEDS_DIR, expected_feed["name"], "index.json")
            ) as f:
                file_contents = f.read()
                expected_groups = json.loads(file_contents)["groups"]

            # iterate over expected groups and verify data
            for expected_group in expected_groups:
                actual_group = find_by_name(
                    actual_feed["groups"], expected_group["name"]
                )
                assert actual_group
                assert actual_group["enabled"]
                assert actual_group["record_count"] == 10

                # get expected cves and query to verify they are present
                with open(
                    os.path.join(
                        FEEDS_DIR,
                        expected_feed["name"],
                        f"{expected_group['name']}.json",
                    )
                ) as f:
                    file_contents = f.read()
                    expected_vulns = json.loads(file_contents)["data"]

                cves = [vuln["Advisory"]["CVE"][0] for vuln in expected_vulns["data"]]

                vuln_response = (
                    policy_engine_api.query_vulnerabilities.get_vulnerabilities(cves)
                )
