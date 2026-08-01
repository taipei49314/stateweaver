# StateWeaver Chain Compiler

The compiler composes evidence-bound, typed transition fragments into a minimal deterministic
candidate chain. It performs no I/O and cannot execute a target. Compiled envelopes are resequenced,
so `requires_policy_reauthorization` is always true: callers must obtain fresh policy decisions
before a candidate can cross the replay adapter boundary.
