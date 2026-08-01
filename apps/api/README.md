# StateWeaver API

`stateweaver-api` is a deliberately small, read-only FastAPI foundation for the public
experience. It serves one built-in **SYNTHETIC LOCAL LAB** saved-run fixture (`sw_demo_01`) for the
Experiment Overview, World DAG, Twin Inspector, and Replay/Evidence Viewer workspaces. The
fixture has a fixed 40-zero commit placeholder, deterministic mode and oracle, zero model calls,
and a local-lab workspace boundary.

The fixture is deterministic and contains no network, filesystem, subprocess, Docker, credential,
or real-target integration. It includes the UI's six fixed stages, `24 → 4 → 2 → 1` world flow,
three required fragments, aligned vulnerable/patched replay lanes, content-bound digests, and five
markers that match the same synthetic fixture signature. The API validates cross-field closure and
the evidence hash binds the canonical saved manifest. This is still sample presentation data only:
it is not a materialized proof, does not execute a scenario, and is not release-certified or M8
certification.

## Run locally

```powershell
uv run --project apps/api uvicorn stateweaver_api.app:app --app-dir apps/api/src
```

The public surface has only these GET routes:

- `/healthz`
- `/v1/demo/overview`
- `/v1/demo/worlds`
- `/v1/demo/twin`
- `/v1/demo/replay`

For a browser-based local UI, CORS accepts only `http://localhost:3000` and
`http://127.0.0.1:3000` and only the `GET` method.
GET routes reject query parameters and request bodies so the demo remains a literal zero-input
surface.
