import logging
from typing import Dict

from tests.functional.services.catalog.utils import catalog_api
from tests.functional.services.utils import http_utils


def add_or_replace_document(bucket: str, archiveid: str, object: Dict):
    try:
        catalog_api.delete_document(bucket, archiveid)
    except http_utils.RequestFailedError as err:
        logging.error(err)
    catalog_api.add_document(bucket, archiveid, object)
