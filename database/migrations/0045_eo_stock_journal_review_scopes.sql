-- Phase 1EO: append-only scope vocabulary extension. No reviewer is auto-granted.
-- Do not edit the checksum-bound predecessor 0044 or promote legal authority.
ALTER TABLE app_reviewer_scope_grants
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL') NOT NULL;
ALTER TABLE app_reviewer_scope_events
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL') NOT NULL;
