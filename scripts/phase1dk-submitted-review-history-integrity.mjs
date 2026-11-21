import {createHash} from 'node:crypto';
import {Buffer} from 'node:buffer';
import {evaluateLatestSubmittedReviews}
 from './phase1co-live-exact-head-reviewer-quorum.mjs';

// Phase 1DK: unsigned fingerprint of the *complete decision-relevant review
// history* retrieved via official GitHub GET pagination. A stable review count
// alone is NOT enough to show review decisions were unchanged.
const SHA=/^[0-9a-f]{40}$/;
const LOGIN=/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const AUTHOR='j9619655391-max';
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
export const REVIEW_HISTORY_DOMAIN='AADI-1DK-OFFICIAL-GITHUB-REVIEW-HISTORY-UNSIGNED-V1\n';
export const MAX_REVIEW_EVENTS=299;
export const MAX_REVIEW_CANONICAL_BYTES=131072;

/**
 * A deterministic projection of all valid submitted + pending GitHub review
 * decisions. The hash intentionally excludes raw review body text and identity
 * lists; usernames only enter the hash preimage. This is not an external
 * signature or privacy-proof anonymous credential. No PII is reported.
 *
 * Request must be complete (all official bounded pagination pages) and
 * correlated to a specific exact 40-hex current PR source HEAD. Reordering
 * returned records without changing decisions does not change the hash.
 *
 * Returns null on any malformed record, unknown state, duplicate ID, missing
 * pagination, invalid HEAD or excessive input; never invents quorum.
 */
export function digestOfficialSubmittedReviewHistory({
 reviews=null,head=null
}={}){
 if(!SHA.test(head??'')||
    reviews?.status!=='read'||reviews.complete!==true||
    !Array.isArray(reviews.data)||
    reviews.data.length>MAX_REVIEW_EVENTS)
  return null;
 // Share the exact source/recency/permission-independent review validity
 // criteria used by 1DC and 1CO; this does not authenticate corporate roles.
 const validation=evaluateLatestSubmittedReviews(reviews.data,head,AUTHOR);
 if(validation.valid!==true)return null;
 try{
  const rows=reviews.data.map(record=>{
   if(!object(record)||!object(record.user)||
      !Number.isSafeInteger(record.id)||record.id<=0||
      !LOGIN.test(record.user.login??''))throw Error('review invalid');
   if(!['PENDING','APPROVED','CHANGES_REQUESTED','COMMENTED','DISMISSED']
       .includes(record.state))throw Error('state invalid');
   // Null pending timestamps and commits are represented explicitly.
   const committed=record.commit_id??null;
   const timestamp=record.submitted_at??null;
   if(committed!==null&&!SHA.test(committed))throw Error('commit invalid');
   if(timestamp!==null&&(typeof timestamp!=='string'||
      !Number.isFinite(Date.parse(timestamp))))throw Error('date invalid');
   return [
    record.id,record.user.login.toLowerCase(),record.state,
    committed,timestamp
   ];
  }).sort((a,b)=>a[0]-b[0]);
  const encoded=JSON.stringify({sourceHead:head,rows});
  if(Buffer.byteLength(encoded,'utf8')>MAX_REVIEW_CANONICAL_BYTES)
   return null;
  return createHash('sha256')
   .update(REVIEW_HISTORY_DOMAIN+encoded,'utf8').digest('hex');
 }catch{return null;}
}
