import json
from os import path
from typing import Dict

import pytest

from tests.functional.services.catalog.utils import catalog_api
from tests.functional.services.policy_engine.utils.utils import (
    AnalysisFile,
)
from tests.functional.services.catalog.utils.utils import add_or_replace_document
from tests.functional.services.policy_engine.utils import images_api
from tests.functional.services.utils import http_utils


CURRENT_DIR = path.dirname(path.abspath(__file__))
ANALYSIS_FILES_DIR = path.join(CURRENT_DIR, "analysis_files")
ANALYSIS_FILES = [
    AnalysisFile(
        "alpine_latest.json",
        "sha256:4661fb57f7890b9145907a1fe2555091d333ff3d28db86c3bb906f6a2be93c87",
    )
]
IMAGE_DIGEST_ID_MAP: Dict[str, str] = {}


@pytest.fixture(scope="session", autouse=True)
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


@pytest.fixture(scope="session")
def image_digest_id_map():
    return IMAGE_DIGEST_ID_MAP
