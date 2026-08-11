"""The M5 producer consumes exact retained M4 bytes before clean-root replay."""

from stateweaver.cli.observed_chain_qualification import M5_REPLAY_COUNT


def test_m5_replay_count_is_fixed() -> None:
    assert M5_REPLAY_COUNT == 5
