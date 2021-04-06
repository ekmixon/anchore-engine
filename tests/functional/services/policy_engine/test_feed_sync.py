import os

import tests.functional.services.policy_engine.utils.api as policy_engine_api
from tests.functional.services.policy_engine.conftest import FEEDS_DATA_PATH_PREFIX
from tests.functional.services.utils import http_utils

# TODO check schema


class TestFeedSync:
    @classmethod
    def _find_by_name(cls, records, name):
        for record in records:
            if record["name"] == name:
                return record
        return None

    @classmethod
    def _get_vuln_ids(cls, expected_vulns):
        vuln_ids = []
        for vuln in expected_vulns:
            if "Advisory" in vuln:
                if "ghsaId" in vuln["Advisory"]:
                    vuln_ids.append(vuln["Advisory"]["ghsaId"])
                else:
                    vuln_ids += vuln["Advisory"]["CVE"]
            if "@id" in vuln:
                vuln_ids.append(vuln["@id"])
            if "cve" in vuln:
                vuln_ids.append(vuln["cve"]["CVE_data_meta"]["ID"])
            if "Vulnerability" in vuln:
                if "Name" in vuln["Vulnerability"]:
                    vuln_ids.append(vuln["Vulnerability"]["Name"])
        return vuln_ids

    def test_expected_feed_sync(self, expected_content, clear_database_temporary):
        feed_sync_resp = policy_engine_api.feeds.feeds_sync()
        assert feed_sync_resp == http_utils.APIResponse(200)
        for feed in feed_sync_resp.body:
            assert feed["status"] == "success"

        feeds_get_resp = policy_engine_api.feeds.get_feeds(True)

        # get feeds index file
        expected_feeds = expected_content(
            os.path.join(FEEDS_DATA_PATH_PREFIX, "index")
        )["feeds"]

        assert len(feeds_get_resp.body) == len(expected_feeds)

        for expected_feed in expected_feeds:
            # assert that expected feed is present in found list and enabled
            actual_feed = self._find_by_name(feeds_get_resp.body, expected_feed["name"])
            assert not isinstance(actual_feed, type(None))
            assert actual_feed["enabled"]

            expected_groups = expected_content(
                os.path.join(FEEDS_DATA_PATH_PREFIX, expected_feed["name"], "index")
            )["groups"]

            # iterate over expected groups and verify data
            for expected_group in expected_groups:
                actual_group = self._find_by_name(
                    actual_feed["groups"], expected_group["name"]
                )
                assert actual_group
                assert actual_group["enabled"]

                # get expected cves and query to verify they are present
                expected_vulns = expected_content(
                    os.path.join(
                        FEEDS_DATA_PATH_PREFIX,
                        expected_feed["name"],
                        expected_group["name"],
                    )
                )["data"]
                assert actual_group["record_count"] == len(expected_vulns)

                vuln_ids = self._get_vuln_ids(expected_vulns)

                vuln_response = (
                    policy_engine_api.query_vulnerabilities.get_vulnerabilities(
                        vuln_ids, namespace=expected_group["name"]
                    )
                )

                assert len(vuln_response.body) == len(expected_vulns)
                assert len(set([x["id"] for x in vuln_response.body])) == len(
                    expected_vulns
                )
