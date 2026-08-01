# StateWeaver Twin

`stateweaver-twin` builds a partial, evidence-bound Security Semantic Twin from
caller-supplied, synthetic inputs. It does not import FastAPI, SQLAlchemy,
OpenTelemetry, or any network client. It never executes an action.

The core accepts a narrow OpenAPI mapping, typed FastAPI/SQLAlchemy-style route
and resource declarations, and typed telemetry/state deltas. It emits sorted,
canonical entities, facts, relations, conflicts, and `TransitionFragment`s.

An `OBSERVED` transition is admitted only when its supplied evidence registry
contains a trusted runtime OTel trace and an observed state-delta artifact. The
fragment retains every referenced evidence ID and a fidelity profile. Source and
runtime facts that disagree become explicit `TwinConflict`s; the builder never
silently chooses a side.

All identifiers, hostnames, paths, and evidence passed to this package are
caller-provided data. Consumers must still apply StateWeaver scope and policy
checks before any typed action could be executed elsewhere.
