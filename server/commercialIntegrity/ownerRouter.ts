import {Router} from 'express';
import type {RowDataPacket} from 'mysql2/promise';
import {getPool} from '../db';
import {requireOwner} from '../auth/router';
import {requirePrivilegedMfa} from '../auth/mfaPolicy';
import {inspectInternalQuoteScope,inspectInternalProcurementScope} from './checks';
import {inspectInternalQuoteHistory} from './quoteHistory';
import {buildLocalQuoteHistoryCommitment} from './quoteAnchors';
import {readCandidateAuthorityExpectedUnderLock,
 inspectCandidateExternalAuthorityDossierOnConnection} from './quoteAuthorityCustody';

// READ ONLY: quote/PO creation and dispatch stay held in server workflows.
// Never accept client prices, audit keys, signatures, recipients, private
// material, "approve" or release authority here.
const router=Router();
router.use(requireOwner);
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function unavailable(res:import('express').Response,e:unknown){
 console.error('Commercial held scope inspection refused',e instanceof Error?e.name:'Unknown');
 res.status(503).json({error:'Commercial source-of-truth inspection unavailable',releaseDecision:'HOLD'});
}

router.get('/quotes/:id',requirePrivilegedMfa,async(req,res)=>{
 if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid draft ID'});return;}
 const db=getPool();
 if(!db){res.status(503).json({error:'Database unavailable',releaseDecision:'HOLD'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const [drafts]=await conn.query<RowDataPacket[]>(
   'SELECT q.*,c.deleted_at AS customer_deleted_at FROM sales_quote_drafts q JOIN crm_customers c ON c.id=q.customer_id WHERE q.id=? AND q.created_by=? FOR UPDATE',
   [req.params.id,res.locals.auth.userId]);
  if(drafts.length!==1){await conn.rollback();res.status(404).json({error:'Draft not available'});return;}
  const [lines]=await conn.query<RowDataPacket[]>(
   'SELECT * FROM sales_quote_draft_items WHERE quote_id=? ORDER BY position',[req.params.id]);
  // Inspect every revision including revision 0, not only the current one.
  // 1002 rows permit detecting oversized histories without unbounded work.
  const [revisions]=await conn.query<RowDataPacket[]>(
   'SELECT * FROM sales_quote_draft_revisions WHERE quote_id=? ORDER BY revision_number ASC LIMIT 1002',
   [req.params.id]);
  const [decisions]=await conn.query<RowDataPacket[]>(
   'SELECT d.*,u.role AS reviewer_role FROM sales_quote_review_decisions d LEFT JOIN auth_users u ON u.id=d.owner_user_id WHERE d.quote_id=? ORDER BY d.revision_number ASC LIMIT 1002',
   [req.params.id]);
  const [preps]=await conn.query<RowDataPacket[]>(
   `SELECT p.*,o.id AS outbox_id,o.event_type,o.dispatch_state,o.payload_sha256,
    (SELECT COUNT(*) FROM sales_quote_outbox_holds c WHERE c.release_preparation_id=p.id) AS outbox_count
    FROM sales_quote_release_preparations p
    LEFT JOIN sales_quote_outbox_holds o ON o.release_preparation_id=p.id
    WHERE p.quote_id=? ORDER BY p.revision_number ASC LIMIT 1002`,[req.params.id]);
  const current=revisions.at(-1)??null;
  const revision=current?Number(current.revision_number):0;
  const currentDecisions=decisions.filter(d=>Number(d.revision_number)===revision);
  const currentPreps=preps.filter(p=>Number(p.revision_number)===revision);
  const truncated=revisions.length>1000||decisions.length>1001||preps.length>1001;
  const result=inspectInternalQuoteScope({
   draft:drafts[0],lines,revision:current,decision:currentDecisions[0]??null,
   preparation:currentPreps[0]??null
  });
  const history=inspectInternalQuoteHistory({
   draft:drafts[0],lines,revisions,decisions,preparations:preps,truncated
  });
  const commitment=truncated?null:buildLocalQuoteHistoryCommitment({
   draft:drafts[0],lines,revisions,decisions,preparations:preps
  });
  const {expected:authorityExpected,bm:checkpoint,bn:reconciliation}=
   await readCandidateAuthorityExpectedUnderLock(conn,req.params.id);
  const dossier=await inspectCandidateExternalAuthorityDossierOnConnection(
   conn,req.params.id,authorityExpected);
  await conn.commit();
  const anomalies=[...new Set([
   ...result.anomalyCodes,
   ...(currentDecisions.length>1?['DUPLICATE_QUOTE_REVIEW']:[]),
   ...(currentPreps.length>1?['DUPLICATE_HELD_PREPARATION']:[]),
   ...history.historyAnomalyCodes,
   ...checkpoint.candidateCheckpointAnomalyCodes,
   ...reconciliation.candidateReconciliationAnomalyCodes,
   ...dossier.candidateAuthorityDossierAnomalyCodes
  ])].sort();
  res.json({...result,...history,...checkpoint,...reconciliation,...dossier,
   localHistoryCommitmentFormat:commitment?.commitmentFormat??null,
   localHistoryCommitmentSha256:commitment?.sourceCommitmentSha256??null,
   localHistoryCommitmentExternallyPublished:false,
   authenticatedWitnessCheckpointAvailable:false,
   independentlyAuthenticatedRevocationAvailable:false,
   localScopeConsistent:result.localScopeConsistent&&history.historyConsistent&&
    checkpoint.candidateCheckpointLocallyConsistent&&
    reconciliation.candidateReconciliationLocallyConsistent&&
    dossier.candidateAuthorityDossierLocallyConsistent&&
    currentDecisions.length<=1&&currentPreps.length<=1,
   anomalyCodes:anomalies,
   sourceType:'INTERNAL_MYSQL_ONLY',
   verifiedIndependentCustomerOrVendorEvidence:false,
   officialQuoteIssued:false});
 }catch(e){await conn.rollback().catch(()=>{});unavailable(res,e);}
 finally{conn.release();}
});

router.get('/procurement/:id',requirePrivilegedMfa,async(req,res)=>{
 if(!uuid.test(req.params.id)){res.status(400).json({error:'Invalid purchase request ID'});return;}
 const db=getPool();
 if(!db){res.status(503).json({error:'Database unavailable',releaseDecision:'HOLD'});return;}
 const conn=await db.getConnection();
 try{
  await conn.beginTransaction();
  const [requests]=await conn.query<RowDataPacket[]>(
   'SELECT r.*,s.status AS supplier_status,s.reviewed_by AS supplier_reviewed_by,s.evidence_ref AS supplier_evidence_ref,s.code AS supplier_code,s.legal_name AS supplier_name,u.role AS supplier_reviewer_role FROM proc_requests r JOIN proc_suppliers s ON s.id=r.supplier_id LEFT JOIN auth_users u ON u.id=s.reviewed_by WHERE r.id=? AND r.created_by=? FOR UPDATE',
   [req.params.id,res.locals.auth.userId]);
  if(requests.length!==1){await conn.rollback();res.status(404).json({error:'Purchase request not available'});return;}
  const [lines]=await conn.query<RowDataPacket[]>(
   'SELECT * FROM proc_request_items WHERE request_id=? ORDER BY position',[req.params.id]);
  const [decisions]=await conn.query<RowDataPacket[]>(
   'SELECT d.*,u.role AS reviewer_role FROM proc_review_decisions d JOIN auth_users u ON u.id=d.reviewer_id WHERE d.request_id=? LIMIT 2',
   [req.params.id]);
  const [holds]=await conn.query<RowDataPacket[]>(
   'SELECT * FROM proc_po_holds WHERE request_id=? LIMIT 2',[req.params.id]);
  const result=inspectInternalProcurementScope({
   request:requests[0],lines,decision:decisions[0]??null,hold:holds[0]??null
  });
  await conn.commit();
  res.json({...result,
   localScopeConsistent:result.localScopeConsistent&&decisions.length<=1&&holds.length<=1,
   anomalyCodes:decisions.length<=1&&holds.length<=1?result.anomalyCodes:
    [...result.anomalyCodes,'DUPLICATE_PURCHASE_REVIEW_OR_HOLD'],
   sourceType:'INTERNAL_MYSQL_ONLY',
   verifiedIndependentSupplierPriceOrCorporateIdentity:false,
   externalSupplierPoDispatch:false});
 }catch(e){await conn.rollback().catch(()=>{});unavailable(res,e);}
 finally{conn.release();}
});
export default router;
