import json
import os
from dataclasses import dataclass
from os import path
from typing import Callable, ContextManager, Dict, Generator, Sequence

import jsonschema
import pytest

import tests.functional.services.catalog.utils.api as catalog_api
import tests.functional.services.policy_engine.utils.api as policy_engine_api
from anchore_engine.db import session_scope
from anchore_engine.db.entities.catalog import CatalogImage, CatalogImageDocker
from anchore_engine.db.entities.common import (
    do_disconnect,
    end_session,
    get_engine,
    initialize,
)
from anchore_engine.db.entities.policy_engine import (
    CpeV2Vulnerability,
    FeedMetadata,
    FixedArtifact,
    NvdV2Metadata,
    Vulnerability,
)
from anchore_engine.db.entities.upgrade import do_create_tables
from tests.functional.services.catalog.utils.utils import add_or_replace_document
from tests.functional.services.utils import http_utils

CURRENT_DIR = path.dirname(path.abspath(__file__))
ANALYSIS_FILES_DIR = path.join(CURRENT_DIR, "analysis_files")
VULN_OUTPUT_DIR = path.join(CURRENT_DIR, "expected_output")
SCHEMA_FILE_DIR = path.join(CURRENT_DIR, "schema_files")
SEED_FILE_DIR = path.join(CURRENT_DIR, "database_seed_files")
FEEDS_DATA_PATH_PREFIX = path.join("data", "v1", "service", "feeds")


@dataclass
class AnalysisFile:
    filename: str
    image_digest: str


ANALYSIS_FILES: Sequence[AnalysisFile] = [
    AnalysisFile(
        "alpine-test.json",
        "sha256:80a31c3ce2e99c3691c27ac3b1753163214494e9b2ca07bfdccf29a5cca2bfbe",
    ),
    AnalysisFile(
        "debian-test.json",
        "sha256:406413437f26223183d133ccc7186f24c827729e1b21adc7330dd43fcdc030b3",
    ),
    AnalysisFile(
        "centos-test.json",
        "sha256:fe3ca35038008b0eac0fa4e686bd072c9430000ab7d7853001bde5f5b8ccf60c",
    ),
]

IMAGE_DIGEST_ID_MAP: Dict[str, str] = {}


@pytest.fixture(scope="module")
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
                policy_engine_api.users.delete_image(image_id)
            except http_utils.RequestFailedError as err:
                if err.status_code != 404:
                    raise err
            IMAGE_DIGEST_ID_MAP[analysis_file.image_digest] = image_id

    def remove_documents_and_image() -> None:
        """
        Cleanup, deletes added images and analyzer manifests.
        """
        for analysis_file in ANALYSIS_FILES:
            catalog_api.objects.delete_document(
                "analysis_data", analysis_file.image_digest
            )
            policy_engine_api.users.delete_image(
                IMAGE_DIGEST_ID_MAP[analysis_file.image_digest]
            )

    request.addfinalizer(remove_documents_and_image)


@pytest.fixture(scope="class")
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
        return policy_engine_api.images.ingress_image(fetch_url, image_id)

    return _ingress_image


@pytest.fixture(scope="class")
def ingress_all_images(ingress_image) -> None:
    """
    Ingress all test images.
    """
    for analysis_file in ANALYSIS_FILES:
        ingress_image(analysis_file.image_digest)


@pytest.fixture(scope="session")
def image_digest_id_map() -> Dict[str, str]:
    """
    :return: lookup mapping of image_digest to image_id
    :rtype: Dict[str, str]
    """
    return IMAGE_DIGEST_ID_MAP


@pytest.fixture
def expected_content(request) -> Callable[[str], Dict]:
    """
    Returns method that will load expected vulnerability response json for a given image_digest
    :rtype: Callable[[str], Dict]
    :return: method that loads expected response json
    """

    def get_expected_content(filename) -> Dict:
        """
        Loads expected vulnerability response json for a given image_digest
        :param filename: name of file from which to load response
        :type filename: str
        :return: expected vulnerability response json
        :rtype: Dict
        """
        module_path = request.module.__file__
        module_filename_with_extension = path.basename(module_path)
        module_filename = path.splitext(module_filename_with_extension)[0]

        file_path = path.join(VULN_OUTPUT_DIR, module_filename, f"{filename}.json")
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
        schema_map = {}
        for file in os.listdir(SCHEMA_FILE_DIR):
            if "schema.json" in file:
                schema = load_jsonschema(file)
                jsonschema.Draft7Validator.check_schema(schema)
                schema_map[schema["$id"]] = schema
        cls.resolver = jsonschema.RefResolver(
            base_uri="", referrer="", store=schema_map
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


@pytest.fixture(scope="session")
def query_by_vuln_jsonschema() -> jsonschema.Draft7Validator:
    """
    Loads jsonschema validator for the get_images_by_vulnerability endpoint.
    :return: jsonschema validator
    :rtype: jsonschema.Draft7Validator
    """
    return SchemaResolver().get_validator("query_by_vulnerability.schema.json")


SEED_FILE_TO_DB_TABLE_MAP: Dict[str, Callable] = {
    "feed_data_vulnerabilities.json": Vulnerability,
    "feed_data_vulnerabilities_fixed_artifacts.json": FixedArtifact,
    "feed_data_nvdv2_vulnerabilities.json": NvdV2Metadata,
    "feed_data_cpev2_vulnerabilities.json": CpeV2Vulnerability,
    "feeds.json": FeedMetadata,
    "catalog_image.json": CatalogImage,
    "catalog_image_docker.json": CatalogImageDocker,
}

SEED_FILE_TO_METADATA_MAP: Dict[str, str] = {
    "feed_data_vulnerabilities.json": "metadata_json",
    "feed_data_vulnerabilities_fixed_artifacts.json": "fix_metadata",
}


@pytest.fixture(scope="session")
def set_env_vars(monkeysession) -> None:
    """
    Setup environment variables for database connection.
    """
    if not os.getenv("ANCHORE_TEST_DB_URL"):
        monkeysession.setenv(
            "ANCHORE_TEST_DB_URL",
            "postgresql://postgres:mysecretpassword@localhost:5432/postgres",
        )


@pytest.fixture(scope="module")
def anchore_db() -> ContextManager[bool]:
    """
    Sets up a db connection to an existing db, and fails if not found/present
    Different from the fixture in test/fixtures.py in that it does not drop existing data upon making a connection
    :return: True after connection setup (not actual connection object).
    :rtype: ContextManager[bool]
    """

    conn_str = os.getenv("ANCHORE_TEST_DB_URL")
    assert conn_str
    config = {"credentials": {"database": {"db_connect": conn_str}}}
    try:
        ret = initialize(localconfig=config)
        yield ret
    finally:
        end_session()
        do_disconnect()


def load_seed_file_rows(file_name: str) -> Generator[Dict, None, None]:
    """
    Loads database seed files (json lines) and yields the json objects.
    :param file_name: name of seed file to load
    :type file_name: str
    :return: generator yields json
    :rtype: Generator[Dict, None, None]
    """
    json_file = os.path.join(SEED_FILE_DIR, file_name)
    with open(json_file, "rb") as f:
        for line in f:
            linetext = line.decode("unicode_escape").strip()
            json_content = json.loads(linetext)
            if file_name in SEED_FILE_TO_METADATA_MAP:
                json_key = SEED_FILE_TO_METADATA_MAP[file_name]
                if json_content[json_key] is not None:
                    json_content[json_key] = json.loads(json_content[json_key])
            yield json_content


def _setup_vuln_data():
    with session_scope() as db:
        all_records = []
        # set up vulnerability data
        for seed_file_name, entry_cls in SEED_FILE_TO_DB_TABLE_MAP.items():
            for db_entry in load_seed_file_rows(seed_file_name):
                all_records.append(entry_cls(**db_entry))
        db.bulk_save_objects(all_records)
        db.flush()


def _teardown_vuln_data():
    tablenames = [cls.__tablename__ for cls in SEED_FILE_TO_DB_TABLE_MAP.values()]
    tablenames_joined = ", ".join(map(str, tablenames))
    engine = get_engine()
    with engine.connect() as connection:
        with connection.begin():
            connection.execute(f"DROP TABLE {tablenames_joined} CASCADE")
    do_create_tables()


@pytest.fixture(scope="module", autouse=True)
def setup_vuln_data(
    request,
    set_env_vars,
    anchore_db,
) -> None:
    """
    Writes database seed file content to database. This allows us to ensure consistent vulnerability results (regardless of feed sync status).
    """
    _teardown_vuln_data()
    _setup_vuln_data()
    request.addfinalizer(_teardown_vuln_data)


@pytest.fixture
def clear_database_temporary(request) -> None:
    _teardown_vuln_data()

    def setup():
        _teardown_vuln_data()
        _setup_vuln_data()

    request.addfinalizer(setup)
