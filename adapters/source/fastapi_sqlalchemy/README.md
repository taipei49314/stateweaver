# FastAPI / SQLAlchemy source adapter

This adapter reads only in-memory framework metadata. It never opens a socket, creates an engine,
executes SQL, imports application modules by name, or follows a URL. FastAPI routes and SQLAlchemy
`Table` objects must already be supplied by the caller, together with an evidence ID for the source
snapshot. The output is the closed, evidence-bound input surface accepted by `stateweaver-twin`.
