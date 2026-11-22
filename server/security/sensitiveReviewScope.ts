import type {PoolConnection,RowDataPacket} from 'mysql2/promise';

// Only app-local OWNER nominations, NOT real CCA, MCA, external identities or
// independent statutory attestation. Read scope before confidential data access;
// use lock=true for a mutation in the same transaction as durable review writes.
export type SensitiveReviewScope='PROOF'|'KEY_LIFECYCLE'|'EXTERNAL_TRUST';
export async function activeSensitiveReviewerScope(
 conn:PoolConnection,ownerId:string,reviewerId:string,
 scope:SensitiveReviewScope,lock=false):Promise<boolean>{
 if(!ownerId||!reviewerId||ownerId===reviewerId)return false;
 const [rows]=await conn.query<RowDataPacket[]>(
  `SELECT g.state FROM app_reviewer_scope_grants g
   JOIN auth_users owner_user ON owner_user.id=g.owner_user_id
   JOIN auth_users reviewer_user ON reviewer_user.id=g.reviewer_user_id
   WHERE g.owner_user_id=? AND g.reviewer_user_id=? AND g.workflow_scope=?
     AND owner_user.role='OWNER' AND owner_user.status='ACTIVE'
     AND reviewer_user.role='REVIEWER' AND reviewer_user.status='ACTIVE'`+
   (lock?' FOR UPDATE':''),
  [ownerId,reviewerId,scope]);
 return rows.length===1&&rows[0].state==='ACTIVE';
}
