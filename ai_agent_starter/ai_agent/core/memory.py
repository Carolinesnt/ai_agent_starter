from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class TestCase:
    method: str
    path: str
    role: str
    self_access: bool
    depth: int = 0
    mutation: Optional[Dict[str, Any]] = None

@dataclass
class Result:
    tc: TestCase
    status_code: int
    body: Dict[str, Any] = field(default_factory=dict)
    ts: float = 0.0
    artifact: Optional[str] = None

@dataclass
class Memory:
    tests: List[TestCase] = field(default_factory=list)
    results: List[Result] = field(default_factory=list)
    # Seeded resource IDs: role -> { key/placeholder: id }
    resource_ids: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def record_test(self, tc: TestCase):
        self.tests.append(tc)

    def record_result(self, res: Result):
        self.results.append(res)

    def store_resource_id(self, role: str, key: str, rid: int):
        if role not in self.resource_ids:
            self.resource_ids[role] = {}
        self.resource_ids[role][key] = rid
        # Add common alias patterns for convenience
        if not key.endswith("_id"):
            self.resource_ids[role][f"{key}_id"] = rid
        if not key.startswith("id_"):
            self.resource_ids[role][f"id_{key}"] = rid
