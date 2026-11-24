-- Phase 1GF: CI-only migration candidate, never repair legacy evidence.
ALTER TABLE crm_audit_events
 ADD COLUMN gf_create_entity_id CHAR(36) GENERATED ALWAYS AS
 (CASE WHEN operation='CREATE' THEN entity_id ELSE NULL END) STORED,
 ADD UNIQUE KEY uq_gf_crm_create_origin (entity_type,gf_create_entity_id)
-- statement-break
ALTER TABLE sales_quote_create_requests ADD UNIQUE KEY uq_gf_quote_binding (quote_id)
-- statement-break
CREATE TRIGGER trg_gf_quote_unbound_insert BEFORE INSERT ON sales_quote_create_requests
FOR EACH ROW
BEGIN
 IF NEW.quote_id IS NOT NULL THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GF_UNBOUND_INSERT_REQUIRED';
 END IF;
END
-- statement-break
CREATE TRIGGER trg_gf_quote_bind_once BEFORE UPDATE ON sales_quote_create_requests
FOR EACH ROW
BEGIN
 IF OLD.quote_id IS NOT NULL OR NEW.quote_id IS NULL
  OR NOT (BINARY OLD.actor_id <=> BINARY NEW.actor_id)
  OR NOT (BINARY OLD.request_key <=> BINARY NEW.request_key)
  OR NOT (BINARY OLD.request_hash <=> BINARY NEW.request_hash)
  OR NOT (OLD.created_at <=> NEW.created_at)
  OR NOT EXISTS (SELECT 1 FROM sales_quote_drafts q WHERE q.id=NEW.quote_id AND q.created_by=NEW.actor_id)
 THEN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='GF_BIND_ONCE_REQUIRED';
 END IF;
END
