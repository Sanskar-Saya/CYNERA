from pydantic import BaseModel, Field
from typing import List, Optional


class ThreatIntelligence(BaseModel):
    title: str
    source: str
    url: str
    published: Optional[str] = None

    summary: Optional[str] = None

    threat_actors: List[str] = Field(default_factory=list)
    malware: List[str] = Field(default_factory=list)

    iocs: List[str] = Field(default_factory=list)
    cves: List[str] = Field(default_factory=list)

    techniques: List[str] = Field(default_factory=list)

    confidence: str = "unknown"


if __name__ == "__main__":
    print("[CYNERA] Intelligence model loaded successfully.")
    print("[CYNERA] ThreatIntelligence schema is ready.")