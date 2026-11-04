"""Unit tests for `summary.json` failure-label qualification in `qa/qa_blackbox.py`."""
from pathlib import Path
import sys
import unittest

QA_ROOT = Path(__file__).resolve().parents[1]
if str(QA_ROOT) not in sys.path:
    sys.path.insert(0, str(QA_ROOT))

from qa_blackbox import qualify_failed_label  # noqa: E402


class QualifyFailedLabelTests(unittest.TestCase):
    def test_unprefixed_label_gains_the_suite_prefix(self) -> None:
        self.assertEqual(
            qualify_failed_label("real", "Rust definition and signature"),
            "real: Rust definition and signature",
        )

    def test_already_prefixed_label_is_not_prefixed_twice(self) -> None:
        self.assertEqual(
            qualify_failed_label("corpus", "corpus: chipsrc symbol coordinates are valid"),
            "corpus: chipsrc symbol coordinates are valid",
        )

    def test_other_suite_prefix_still_gains_its_own_prefix(self) -> None:
        self.assertEqual(
            qualify_failed_label("scale", "sfc: jsx rename"),
            "scale: sfc: jsx rename",
        )

    def test_prefix_must_match_the_suite_name_exactly(self) -> None:
        self.assertEqual(
            qualify_failed_label("sfc", "corpus: work inspect and convert counts agree"),
            "sfc: corpus: work inspect and convert counts agree",
        )


if __name__ == "__main__":
    unittest.main()
