import json
from os import path
from typing import Dict

import jsonschema
import pytest

from tests.functional.services.catalog.utils import catalog_api
from tests.functional.services.catalog.utils.utils import add_or_replace_document
from tests.functional.services.policy_engine.utils import images_api
from tests.functional.services.policy_engine.utils.utils import AnalysisFile
from tests.functional.services.utils import http_utils

CURRENT_DIR = path.dirname(path.abspath(__file__))
ANALYSIS_FILES_DIR = path.join(CURRENT_DIR, "analysis_files")
VULN_OUTPUT_DIR = path.join(CURRENT_DIR, "expected_output")
ANALYSIS_FILES = [
    AnalysisFile(
        "alpine_latest.json",
        "sha256:4661fb57f7890b9145907a1fe2555091d333ff3d28db86c3bb906f6a2be93c87",
    ),
    AnalysisFile(
        "centos_8.json",
        "sha256:dbbacecc49b088458781c16f3775f2a2ec7521079034a7ba499c8b0bb7f86875",
    ),
    AnalysisFile(
        "node_15_12_0.json",
        "sha256:88ef7fa504af971315e02eea173a9df690e9e0a0c9591af3ed62a9c5e0bb8217",
    ),
]
IMAGE_DIGEST_ID_MAP: Dict[str, str] = {}


@pytest.fixture
def add_catalog_documents(request) -> None:
    for analysis_file in ANALYSIS_FILES:
        file_path = path.join(ANALYSIS_FILES_DIR, analysis_file.filename)
        with open(file_path, "r") as f:
            file_contents = f.read()
            analysis_document = json.loads(file_contents)
            add_or_replace_document(
                "analysis_data", analysis_file.image_digest, analysis_document
            )
            image_id = analysis_document["document"][0]["image"]["imageId"]
            try:
                images_api.delete_image(image_id)
            except http_utils.RequestFailedError as err:
                if err.status_code != 404:
                    raise err
            IMAGE_DIGEST_ID_MAP[analysis_file.image_digest] = image_id

    def remove_documents_and_image():
        for analysis_file in ANALYSIS_FILES:
            catalog_api.delete_document("analysis_data", analysis_file.image_digest)
            images_api.delete_image(IMAGE_DIGEST_ID_MAP[analysis_file.image_digest])

    request.addfinalizer(remove_documents_and_image)


@pytest.fixture
def ingress_image(add_catalog_documents):
    def _ingress_image(image_digest: str):
        fetch_url = f"catalog://{http_utils.DEFAULT_API_CONF['ANCHORE_API_ACCOUNT']}/analysis_data/{image_digest}"
        image_id = IMAGE_DIGEST_ID_MAP[image_digest]
        return images_api.ingress_image(fetch_url, image_id)

    return _ingress_image


@pytest.fixture(scope="session")
def image_digest_id_map():
    return IMAGE_DIGEST_ID_MAP


VULNERABILITY_JSONSCHEMA = {
    "type": "object",
    "required": ["cpe_report", "image_id", "legacy_report"],
    "properties": {
        "cpe_report": {"type": "array"},
        "image_id": {"type": "string"},
        "legacy_report": {
            "type": "object",
            "required": ["multi"],
            "properties": {
                "multi": {
                    "type": "object",
                    "required": ["result", "url_column_index", "warns"],
                    "properties": {
                        "result": {
                            "type": "object",
                            "required": ["colcount", "header", "rowcount", "rows"],
                            "properties": {
                                "colcount": {"type": "number"},
                                "header": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "rowcount": {"type": "number"},
                                "rows": {"type": "array"},
                            },
                        },
                        "url_column_index": {"type": "number"},
                        "warns": {"type": "array"},
                    },
                }
            },
        },
        "user_id": {"type": "string"},
    },
}

INGRESS_JSONSCHEMA = {
    "type": "object",
    "required": ["status", "vulnerability_report"],
    "properties": {
        "status": {"type": "string"},
        "vulnerability_report": VULNERABILITY_JSONSCHEMA,
    },
}


@pytest.fixture
def vulnerability_jsonschema():
    jsonschema.Draft7Validator.check_schema(VULNERABILITY_JSONSCHEMA)
    return jsonschema.Draft7Validator(VULNERABILITY_JSONSCHEMA)


@pytest.fixture
def ingress_jsonschema():
    jsonschema.Draft7Validator.check_schema(INGRESS_JSONSCHEMA)
    return jsonschema.Draft7Validator(INGRESS_JSONSCHEMA)


@pytest.fixture
def expected_content():
    def get_expected_content(image_digest):
        file_path = path.join(VULN_OUTPUT_DIR, f"{image_digest}.json")
        with open(file_path, "r") as f:
            file_contents = f.read()
            return json.loads(file_contents)

    return get_expected_content
