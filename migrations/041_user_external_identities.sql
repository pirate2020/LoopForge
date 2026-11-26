-- External identity mappings for IAM single sign-on.
--
-- The platform creates this table automatically on startup through gorm's
-- incremental DDL. This script is for operators who pre-create the baseline
-- schema for an external MySQL database before starting the new binary.
--
-- subject_hash is SHA-256(subject) in lowercase hex. It is the lookup key so
-- the mapping stays case-sensitive under MySQL's case-insensitive default
-- collation; subject is retained for operator inspection.
CREATE TABLE IF NOT EXISTS user_external_identities (
  provider VARCHAR(32) NOT NULL,
  subject_hash CHAR(64) NOT NULL,
  subject VARCHAR(255) NOT NULL,
  user_id BIGINT NOT NULL,
  created_at DATETIME(3) NULL,
  updated_at DATETIME(3) NULL,
  PRIMARY KEY (provider, subject_hash),
  UNIQUE KEY uq_user_external_identities_user (provider, user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
