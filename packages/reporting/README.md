# StateWeaver reporting

This package turns one valid in-memory Reality pre-receipt candidate into a deterministic
publication candidate. The output contains the exact pre-receipt artifacts, serialized receipt,
pre-receipt manifest, and a `report.md` whose artifact table links every claim back to retained
bytes. A final canonical manifest binds that closed payload without recursively listing itself.

The builder and verifier accept bytes and in-memory mappings only. They do not read or write the
filesystem, call a provider, authenticate an issuer, or promote a Finding. A verified publication
therefore remains `authoritative=False`, `promotable=False`, and `attested=False`. It demonstrates
deterministic internal coherence, not M6 certification or clean-machine reproduction.
