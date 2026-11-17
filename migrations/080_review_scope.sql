-- 080 (core): what a reviewer actually saw. domains.hostnames keeps growing after a review (new CT/CZDS
-- certificates for the same registrable domain); a "not a scam" decision must cover only the hostnames that
-- were on the row when the reviewer decided, not ones added later (shared platforms issue per-site certs).
-- NULL = reviewed before this column existed (or never reviewed): readers fall back to hostnames.
ALTER TABLE domains ADD COLUMN IF NOT EXISTS reviewed_hostnames text[];
