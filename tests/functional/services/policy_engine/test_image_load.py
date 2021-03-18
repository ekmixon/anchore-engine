import pytest

from tests.functional.services.policy_engine.utils.images_api import ingress_image
from tests.functional.services.utils.http_utils import APIResponse, DEFAULT_API_CONF


class TestImageLoad:
    @pytest.mark.parametrize(
        "image_digest",
        [
            "sha256:4661fb57f7890b9145907a1fe2555091d333ff3d28db86c3bb906f6a2be93c87",
        ],
    )
    def test_image_load(self, image_digest, image_digest_id_map):
        fetch_url = f"catalog://{DEFAULT_API_CONF['ANCHORE_API_ACCOUNT']}/analysis_data/{image_digest}"
        image_id = image_digest_id_map[image_digest]
        resp = ingress_image(fetch_url, image_id)
        assert resp == APIResponse(200)
        assert resp.body.get("status") == "loaded"
