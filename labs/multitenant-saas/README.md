# StateWeaver multi-tenant SaaS lab

This package is a deterministic, in-process FastAPI target. It intentionally
models one narrow authorization flaw without outbound networking, arbitrary
URLs, filesystem access, subprocesses, dynamic code execution, or real
credentials.

The vulnerable mode discloses a synthetic Tenant B document only when every
stateful prerequisite is present: an old Tenant A editor session was retained,
an authorization decision was cached, an admin downgraded the user, the
propagation job was deliberately delayed, Tenant B published and Tenant A
claimed an opaque document reference, and replay occurs inside the controlled
clock window. The patched mode accepts the same setup actions but enforces the
current tenant policy at the final object read.

```python
from stateweaver_lab import create_app

vulnerable = create_app("vulnerable")
patched = create_app("patched")
```

Bearer values are public synthetic fixture identifiers defined in
`stateweaver_lab.fixtures`. Application state, evidence, fingerprints, and
oracle output store internal session IDs only and never retain the bearer
header value.

Run the package-local suite with:

```text
python -m pytest -q
```

The suite uses FastAPI's in-process test transport. It does not open a socket
or contact any external target.
