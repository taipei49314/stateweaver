CREATE TABLE IF NOT EXISTS sw_state (
    id integer PRIMARY KEY CHECK (id BETWEEN 1 AND 16),
    tenant text NOT NULL CHECK (tenant ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    value text NOT NULL CHECK (value ~ '^[a-z0-9][a-z0-9._-]{0,63}$')
);

INSERT INTO sw_state (id, tenant, value)
VALUES (1, 'alpha', 'baseline')
ON CONFLICT (id) DO UPDATE SET tenant = EXCLUDED.tenant, value = EXCLUDED.value;

CREATE TABLE IF NOT EXISTS sw_lab_checkpoint (
    generation text PRIMARY KEY CHECK (generation ~ '^[0-9a-f]{64}$'),
    checkpoint_digest text NOT NULL CHECK (checkpoint_digest ~ '^sha256:[0-9a-f]{64}$'),
    storage_digest text NOT NULL CHECK (storage_digest ~ '^sha256:[0-9a-f]{64}$'),
    checkpoint_base64 text NOT NULL CHECK (octet_length(checkpoint_base64) <= 174764)
);

CREATE TABLE IF NOT EXISTS sw_lab_checkpoint_active (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    active_generation text NULL REFERENCES sw_lab_checkpoint(generation)
);

INSERT INTO sw_lab_checkpoint_active (singleton, active_generation)
VALUES (true, NULL)
ON CONFLICT (singleton) DO NOTHING;
