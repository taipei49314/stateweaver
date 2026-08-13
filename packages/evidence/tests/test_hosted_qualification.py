"""Hosted M2-M5 admission must remain exact-SHA and fail closed."""

from stateweaver.evidence.hosted_qualification import HOSTED_QUALIFICATION_ADMISSION_PATH


def test_hosted_qualification_path_is_fixed() -> None:
    assert (
        HOSTED_QUALIFICATION_ADMISSION_PATH == "qualification/hosted/docker-compose-admission.json"
    )
