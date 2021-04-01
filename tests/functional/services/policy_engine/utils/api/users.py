from tests.functional.services.policy_engine.utils.api.conf import (
    policy_engine_api_conf,
)
from tests.functional.services.utils import http_utils


def delete_image(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    delete_image_resp = http_utils.http_del(
        ["users", policy_engine_api_conf().get("ANCHORE_API_USER"), "images", image_id],
        config=policy_engine_api_conf,
    )

    if delete_image_resp.code > 300:
        raise http_utils.RequestFailedError(
            delete_image_resp.url, delete_image_resp.code, delete_image_resp.body
        )

    return delete_image_resp


def get_image_vulnerabilities(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    image_vulnerabilities_resp = http_utils.http_get(
        [
            "users",
            policy_engine_api_conf().get("ANCHORE_API_USER"),
            "images",
            image_id,
            "vulnerabilities",
        ],
        config=policy_engine_api_conf,
    )

    if image_vulnerabilities_resp.code > 300:
        raise http_utils.RequestFailedError(
            image_vulnerabilities_resp.url,
            image_vulnerabilities_resp.code,
            image_vulnerabilities_resp.body,
        )

    return image_vulnerabilities_resp
