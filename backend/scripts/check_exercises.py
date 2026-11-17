import sys

from app.explanations.grouping import group_findings
from app.exercises import EXERCISES
from app.scanner import scan_with_status


def classes_found(findings):
    return sorted({issue.vulnerability_class for issue in group_findings(findings)})


def main():
    bad = 0
    print(f"{'exercise':26} {'vulnerable code':34} {'reference fix':34} verdict")
    for exercise in EXERCISES:
        before = scan_with_status(exercise.vulnerable_code, exercise.language)
        after = scan_with_status(exercise.reference_fix, exercise.language)
        before_classes = classes_found(before.findings)
        after_classes = classes_found(after.findings)
        detected = exercise.vulnerability_class in before_classes
        fixed = exercise.vulnerability_class not in after_classes
        complete = before.complete and after.complete
        verdict = "OK" if (detected and fixed and complete) else "PROBLEM"
        if verdict != "OK":
            bad += 1
        before_text = ("found " if detected else "MISSED ") + ",".join(before_classes)
        after_text = ("clean " if fixed else "STILL FLAGGED ") + ",".join(after_classes)
        print(f"{exercise.id:26} {before_text:34} {after_text:34} {verdict}")
        if not complete:
            print("   detector status:", before.detectors, after.detectors)
    print(f"\n{len(EXERCISES) - bad} of {len(EXERCISES)} exercises verified")
    sys.exit(1 if bad else 0)


main()