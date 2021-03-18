import os

from tests.functional.services.utils import http_utils

POLICY_ENGINE_API_CONF = http_utils.DEFAULT_API_CONF.copy()
POLICY_ENGINE_API_CONF["ANCHORE_BASE_URL"] = os.environ.get(
    "ANCHORE_POLICY_ENGINE_URL", "http://localhost:8231/v1"
)


def policy_engine_api_conf():
    return POLICY_ENGINE_API_CONF


def ingress_image(fetch_url: str, image_id: str) -> http_utils.APIResponse:
    if not fetch_url:
        raise ValueError("Cannot ingress image to policy engine without fetch url")

    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    payload = {
        "fetch_url": fetch_url,
        "user_id": POLICY_ENGINE_API_CONF.get("ANCHORE_API_USER"),
        "image_id": image_id,
    }

    ingress_image_resp = http_utils.http_post(
        ["images"], payload, config=policy_engine_api_conf
    )

    if ingress_image_resp.code != 200:
        raise http_utils.RequestFailedError(
            ingress_image_resp.url, ingress_image_resp.code, ingress_image_resp.body
        )

    return ingress_image_resp


def delete_image(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    delete_image_resp = http_utils.http_del(
        ["users", POLICY_ENGINE_API_CONF.get("ANCHORE_API_USER"), "images", image_id],
        config=policy_engine_api_conf,
    )

    if delete_image_resp.code > 300:
        raise http_utils.RequestFailedError(
            delete_image_resp.url, delete_image_resp.code, delete_image_resp.body
        )

    return delete_image_resp


def get_image_vulnerabilites(image_id: str) -> http_utils.APIResponse:
    if not image_id:
        raise ValueError("Cannot ingress image to policy engine without image id")

    image_vulnerabilities_resp = http_utils.http_get(
        [
            "users",
            POLICY_ENGINE_API_CONF.get("ANCHORE_API_USER"),
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
