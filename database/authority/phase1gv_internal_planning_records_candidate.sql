-- Disposable CI only, not a migration.
CREATE TABLE planning_records_gv_candidate (
 id CHAR(36) CHARACTER SET ascii COLLATE ascii_bin PRIMARY KEY,
 actor_id CHAR(36) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
 request_key CHAR(36) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 module CHAR(3) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 request_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 result_json MEDIUMTEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
 result_sha256 CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
 created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
 UNIQUE KEY uq_gv_actor_key(actor_id,request_key),
 KEY ix_gv_actor_created(actor_id,created_at,id),
 CHECK (module IN ('M05','M13','M14','M15','M18','M19','M20','M21','M22','M23','M24','M25')),
 CHECK (JSON_VALID(result_json)), CHECK (OCTET_LENGTH(result_json)<=65536)
) ENGINE=InnoDB
-- statement-break
CREATE TRIGGER aaditech_gv_planning_no_update BEFORE UPDATE ON planning_records_gv_candidate
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GV_RECORD_IMMUTABLE'
-- statement-break
CREATE TRIGGER aaditech_gv_planning_no_delete BEFORE DELETE ON planning_records_gv_candidate
FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GV_RECORD_IMMUTABLE'
