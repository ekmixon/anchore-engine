from dataclasses import dataclass


@dataclass
class AnalysisFile:
    filename: str
    image_digest: str
