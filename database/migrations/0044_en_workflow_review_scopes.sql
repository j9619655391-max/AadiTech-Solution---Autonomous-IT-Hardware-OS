-- Phase 1EN: additive extension of existing 1EL actor scoped reviewer workflow.
-- No retroactive assignments. Existing QUOTES and PROCUREMENT grants unchanged.
-- Internal app nomination only, NOT certified legal authority.
ALTER TABLE app_reviewer_scope_grants
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE') NOT NULL;
ALTER TABLE app_reviewer_scope_events
 MODIFY COLUMN workflow_scope
 ENUM('QUOTES','PROCUREMENT','INTAKE','DISPATCH','EVIDENCE') NOT NULL;
