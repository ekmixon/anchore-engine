import json
import os
from dataclasses import dataclass
from os import path
from typing import Callable, Dict

import jsonschema
import pytest

from anchore_engine.db import session_scope
from anchore_engine.db.entities.common import (do_disconnect, end_session,
                                               initialize)
from anchore_engine.db.entities.policy_engine import Vulnerability
from tests.functional.services.catalog.utils import catalog_api
from tests.functional.services.catalog.utils.utils import \
    add_or_replace_document
from tests.functional.services.policy_engine.utils import images_api
from tests.functional.services.utils import http_utils

CURRENT_DIR = path.dirname(path.abspath(__file__))
ANALYSIS_FILES_DIR = path.join(CURRENT_DIR, "analysis_files")
VULN_OUTPUT_DIR = path.join(CURRENT_DIR, "expected_output")
SCHEMA_FILE_DIR = path.join(CURRENT_DIR, "schema_files")


@dataclass
class AnalysisFile:
    filename: str
    image_digest: str


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
    AnalysisFile(
        "alpine-test.json",
        "sha256:6a05b0ba5f0874b66749628e38f9c2a37ed76c4a4388171d79e0ffe012b90509"
    )
]

IMAGE_DIGEST_ID_MAP: Dict[str, str] = {}


@pytest.fixture
def add_catalog_documents(request) -> None:
    """
    Adds analyzer manifests to catalog. Deletes existing manifests and images if they exist.
    """
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

    def remove_documents_and_image() -> None:
        """
        Cleanup, deletes added images and analyzer manifests.
        """
        for analysis_file in ANALYSIS_FILES:
            catalog_api.delete_document("analysis_data", analysis_file.image_digest)
            images_api.delete_image(IMAGE_DIGEST_ID_MAP[analysis_file.image_digest])

    request.addfinalizer(remove_documents_and_image)


@pytest.fixture
def ingress_image(add_catalog_documents) -> Callable[[str], http_utils.APIResponse]:
    """
    Returns method that adds new image to policy engine for vulnerability scanning. Moved to fixture to reduce code duplication.
    :return: METHOD that calls ingress_image for the policy engine API with the appropriate catalog URL
    :rtype: Callable[[str], http_utils.APIResponse]
    """

    def _ingress_image(image_digest: str) -> http_utils.APIResponse:
        """
        Adds new image to policy engine for vulnerability scanning. Moved to fixture to reduce code duplication.
        :param image_digest: image digest of image to ingress
        :type image_digest: str
        :return: api response
        :rtype: http_utils.APIResponse
        """
        fetch_url = f"catalog://{http_utils.DEFAULT_API_CONF['ANCHORE_API_ACCOUNT']}/analysis_data/{image_digest}"
        image_id = IMAGE_DIGEST_ID_MAP[image_digest]
        return images_api.ingress_image(fetch_url, image_id)

    return _ingress_image


@pytest.fixture(scope="session")
def image_digest_id_map() -> Dict[str, str]:
    """
    :return: lookup mapping of image_digest to image_id
    :rtype: Dict[str, str]
    """
    return IMAGE_DIGEST_ID_MAP


@pytest.fixture
def expected_content() -> Callable[[str], Dict]:
    """
    Returns method that will load expected vulnerability response json for a given image_digest
    :rtype: Callable[[str], Dict]
    :return: method that loads expected response json
    """

    def get_expected_content(image_digest) -> Dict:
        """
        Loads expected vulnerability response json for a given image_digest
        :param image_digest: image digest for which to load response
        :type image_digest: str
        :return: expected vulnerability response json
        :rtype: Dict
        """
        file_path = path.join(VULN_OUTPUT_DIR, f"{image_digest}.json")
        with open(file_path, "r") as f:
            file_contents = f.read()
            return json.loads(file_contents)

    return get_expected_content


def load_jsonschema(filename) -> Dict:
    """
    Load a jsonschema from file
    :param filename: name of jsonschema file to load
    :type filename: str
    :return: schema json as dict
    :rtype: Dict
    """
    file_path = path.join(SCHEMA_FILE_DIR, filename)
    with open(file_path, "r") as f:
        file_contents = f.read()
    schema = json.loads(file_contents)
    return schema


class SchemaResolver:
    """
    Singleton class that wraps the jsonschema loading logic, which allows us to only have to load and check the jsonschema files once.
    """

    _instance = None
    resolver = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SchemaResolver, cls).__new__(cls)
            cls._resolve()
        return cls._instance

    @classmethod
    def _resolve(cls) -> None:
        """
        Load jsonschema files, check that the schemas are valid, and create schema resolver.
        """
        vulnerability_schema = load_jsonschema("vulnerability_report.schema.json")
        ingress_schema = load_jsonschema("ingress_vulnerability_report.schema.json")
        jsonschema.Draft7Validator.check_schema(vulnerability_schema)
        jsonschema.Draft7Validator.check_schema(ingress_schema)
        schema_map = {
            vulnerability_schema["$id"]: vulnerability_schema,
            ingress_schema["$id"]: ingress_schema,
        }
        cls.resolver = jsonschema.RefResolver.from_schema(
            ingress_schema, store=schema_map
        )

    @classmethod
    def get_schema(cls, url: str) -> Dict:
        """
        Retrieves a given schema file
        :param url: name of the schema file to retrieve
        :type url: str
        :return: schema
        :rtype: Dict
        """
        return cls.resolver.resolve_from_url(url)

    @classmethod
    def get_validator(cls, url) -> jsonschema.Draft7Validator:
        """
        Creates the validator for a given schema
        :param url: name of the schema validator to create
        :type url: str
        :return: jsonschema validator
        :rtype: jsonschema.Draft7Validator
        """
        return jsonschema.Draft7Validator(cls.get_schema(url), resolver=cls.resolver)


@pytest.fixture(scope="session")
def vulnerability_jsonschema() -> jsonschema.Draft7Validator:
    """
    Loads jsonschema validator for the get_image_vulnerabilities endpoint.
    :return: jsonschema validator
    :rtype: jsonschema.Draft7Validator
    """
    return SchemaResolver().get_validator("vulnerability_report.schema.json")


@pytest.fixture(scope="session")
def ingress_jsonschema() -> jsonschema.Draft7Validator:
    """
    Loads jsonschema validator for the image_ingress endpoint.
    :return: jsonschema validator
    :rtype: jsonschema.Draft7Validator
    """
    return SchemaResolver().get_validator("ingress_vulnerability_report.schema.json")


@pytest.fixture()
def set_env_var(monkeypatch):
    monkeypatch.setenv("ANCHORE_TEST_DB_URL", "postgresql://postgres:mysecretpassword@localhost:5432/postgres")


@pytest.fixture
def anchore_db(connection_str=None, do_echo=False):
    """
    Sets up a db connection to an existing db, and fails if not found/present
    :return:
    """

    conn_str = connection_str if connection_str else os.getenv("ANCHORE_TEST_DB_URL")

    config = {"credentials": {"database": {"db_connect": conn_str, "db_echo": do_echo}}}

    try:
        ret = initialize(localconfig=config)

        yield ret
    finally:
        end_session()
        do_disconnect()


@pytest.fixture(scope="session")
def insert(set_env_var, anchore_db):
    with session_scope() as db:
        vuln = Vulnerability(id="zan-vijay", namespace_name="centos", severity="Low")
        db.add(vuln)
        db.flush()
