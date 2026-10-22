-- Optional manual migration against the global Darkstar database.
-- The application also applies this additive change during registry setup.
ALTER TABLE users
    ADD COLUMN IF NOT EXISTS theme VARCHAR(32) NOT NULL DEFAULT 'darkstar';
