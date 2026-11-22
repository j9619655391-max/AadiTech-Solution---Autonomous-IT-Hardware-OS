-- Phase 1EP: app-local reviewer scopes for offline proof, key lifecycle and external trust.
-- Safe append-only ENUM; no historical assignments, external CA authority or auto-grants.
ALTER TABLE app_reviewer_scope_grants
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL','PROOF','KEY_LIFECYCLE','EXTERNAL_TRUST') NOT NULL;
ALTER TABLE app_reviewer_scope_events
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE','STOCK','JOURNAL','PROOF','KEY_LIFECYCLE','EXTERNAL_TRUST') NOT NULL;
