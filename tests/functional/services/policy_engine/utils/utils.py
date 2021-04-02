from dataclasses import dataclass
from typing import List, Optional


@dataclass
class ImagesByVulnerabilityQueryOptions:
    severity: Optional[str] = None
    namespace: Optional[str] = None
    affected_package: Optional[str] = None
    vendor_only: bool = True


@dataclass
class ImagesByVulnerabilityQuery:
    vulnerability_id: str
    query_metadata: Optional[ImagesByVulnerabilityQueryOptions]
    affected_images: List[str]
