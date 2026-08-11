CREATE TABLE IF NOT EXISTS sw_state (
    id integer PRIMARY KEY CHECK (id BETWEEN 1 AND 16),
    tenant text NOT NULL CHECK (tenant ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    value text NOT NULL CHECK (value ~ '^[a-z0-9][a-z0-9._-]{0,63}$')
);

INSERT INTO sw_state (id, tenant, value)
VALUES (1, 'alpha', 'baseline')
ON CONFLICT (id) DO UPDATE SET tenant = EXCLUDED.tenant, value = EXCLUDED.value;
