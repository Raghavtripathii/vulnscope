import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict

from app.explanations.classification import HARDCODED_SECRET, OTHER
from app.explanations.gemini_client import ExplainerError, QuotaExceededError
from app.explanations.grouping import Issue, group_findings
from app.explanations.redaction import redact
from app.explanations.schema import Explanation

logger = logging.getLogger(__name__)


def cache_key(issue: Issue, language: str) -> str:
    snippet = redact(
        (issue.code_snippet or "").strip(),
        mask_all_strings=issue.vulnerability_class == HARDCODED_SECRET,
    )
    rule_ids = sorted({item.get("rule_id") or "" for item in issue.evidence})
    raw = json.dumps([language, issue.vulnerability_class, issue.cwe, rule_ids, snippet])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def fix_still_triggers(issue: Issue, fix_issues: list[Issue]) -> bool:
    original_rules = {item.get("rule_id") for item in issue.evidence}
    for fixed in fix_issues:
        if fixed.vulnerability_class != OTHER:
            return True
        if issue.cwe and fixed.cwe == issue.cwe:
            return True
        if original_rules & {item.get("rule_id") for item in fixed.evidence}:
            return True
    return False


class ExplanationService:
    def __init__(
        self,
        static,
        scan_fn,
        llm=None,
        cache_size: int = 500,
        quota_cooldown_seconds: float = 300.0,
        clock=time.monotonic,
    ):
        self.static = static
        self.scan_fn = scan_fn
        self.llm = llm
        self.cache_size = cache_size
        self.quota_cooldown_seconds = quota_cooldown_seconds
        self.clock = clock
        self.cache: OrderedDict[str, Explanation] = OrderedDict()
        self.blocked_until = 0.0
        self.lock = threading.Lock()

    def cache_get(self, key: str) -> Explanation | None:
        with self.lock:
            found = self.cache.get(key)
            if found is None:
                return None
            self.cache.move_to_end(key)
            return found.model_copy()

    def cache_put(self, key: str, explanation: Explanation) -> None:
        with self.lock:
            self.cache[key] = explanation.model_copy()
            self.cache.move_to_end(key)
            while len(self.cache) > self.cache_size:
                self.cache.popitem(last=False)

    def llm_is_blocked(self) -> bool:
        with self.lock:
            return self.clock() < self.blocked_until

    def start_cooldown(self) -> None:
        with self.lock:
            self.blocked_until = self.clock() + self.quota_cooldown_seconds

    def fix_is_clean(self, issue: Issue, candidate: Explanation, language: str) -> bool:
        try:
            findings = self.scan_fn(candidate.fixed_code_example, language)
        except Exception as error:
            logger.warning("could not re-scan the suggested fix: %s", type(error).__name__)
            return False
        if fix_still_triggers(issue, group_findings(findings)):
            logger.info("suggested fix still triggers a finding, using the written explanation")
            return False
        return True

    def explain(self, issue: Issue, language: str) -> Explanation:
        if self.llm is None:
            return self.static.explain(issue, language)

        key = cache_key(issue, language)
        cached = self.cache_get(key)
        if cached is not None:
            return cached

        if self.llm_is_blocked():
            return self.static.explain(issue, language)

        try:
            candidate = self.llm.explain(issue, language)
        except QuotaExceededError:
            self.start_cooldown()
            logger.warning("model quota reached, using written explanations for the next %s seconds", self.quota_cooldown_seconds)
            return self.static.explain(issue, language)
        except ExplainerError as error:
            logger.warning("model explanation failed: %s", error)
            return self.static.explain(issue, language)

        if not self.fix_is_clean(issue, candidate, language):
            return self.static.explain(issue, language)

        checked = candidate.model_copy(update={"fix_rescan": "clean"})
        self.cache_put(key, checked)
        return checked.model_copy()