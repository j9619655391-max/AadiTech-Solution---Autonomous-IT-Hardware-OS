// Phase 1P: real Chromium UI journey on synthetic isolated MySQL; never connect to a deployment.
import assert from 'node:assert/strict';
import {randomUUID,randomBytes} from 'node:crypto';
import {chromium} from 'playwright';
import {getPool} from '../server/db.ts';
import {hashPassword,hashToken} from '../server/auth/crypto.ts';
import {generateTotpSecret,encryptSecret,totpAt} from '../server/auth/totp.ts';

if(process.env.BROWSER_E2E_CI!=='1'||process.env.CRM_TEST_DB!=='1'||
   process.env.DB_NAME!=='aaditech_ci'||process.env.NODE_ENV!=='test')
 throw Error('Browser smoke allowed only for disposable CI MySQL');
const base=process.env.BROWSER_E2E_BASE_URL;
if(base!=='http://127.0.0.1:3000')throw Error('Browser smoke must use fixed loopback app URL');
const db=getPool();if(!db)throw Error('Disposable MySQL unavailable');
let browserInstance;
const password='Browser-Only-Test-Strong-Password-2026';
const created=[];
async function createUser(role){
 const id=randomUUID(),secret=generateTotpSecret();
 const email='browser-'+role.toLowerCase()+'-'+id.slice(0,8)+'@example.invalid';
 await db.execute('INSERT INTO auth_users (id,email,full_name,password_hash,role,status) VALUES (?,?,?,?,?,?)',
  [id,email,role+' Browser CI',await hashPassword(password),role,'ACTIVE']);
 await db.execute('INSERT INTO auth_totp_credentials (user_id,secret_encrypted,enabled_at) VALUES (?,?,UTC_TIMESTAMP(3))',
  [id,encryptSecret(secret)]);
 created.push(id);
 return {id,email,secret,role};
}
async function beginPasswordLogin(page,user,providedPassword=password){
 await page.getByLabel('Work email').fill(user.email);
 await page.getByLabel('Password',{exact:true}).fill(providedPassword);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
}
async function signIn(page,user){
 await beginPasswordLogin(page,user);
 await page.getByRole('heading',{name:'Authenticator verification'}).waitFor();
 // An MFA challenge is not an authenticated session.
 const pending=await page.request.get(base+'/api/auth/me');
 assert.equal(pending.status(),401);
 // Enter an invalid recovery code first: the browser must render an error, not a session.
 const factorInput=page.getByRole('textbox',{name:'Authenticator or recovery code'});
 await factorInput.fill('FFFFFFFFFFFFFFFFFFFF');
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByRole('alert').waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 const code=totpAt(user.secret,Math.floor(Date.now()/30000));
 await factorInput.fill(code);
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByText('Signed in: '+user.email+' · '+user.role).waitFor();
 const active=await page.request.get(base+'/api/auth/me');
 assert.equal(active.status(),200);
 const data=await active.json();
 assert.equal(data.user.role,user.role);
 return data;
}
async function signOut(page){
 const confirmed=page.waitForResponse(response=>
  response.url().endsWith('/api/auth/logout')&&response.request().method()==='POST');
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 const logoutReply=await confirmed;
 assert.equal(logoutReply.status(),204,'Backend must confirm session revocation');
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 const loggedOut=await page.request.get(base+'/api/auth/me');
 assert.equal(loggedOut.status(),401,'Logout must invalidate server-side session');
}

try{
 const owner=await createUser('OWNER'),reviewer=await createUser('REVIEWER');
 // GitHub-hosted runner's installed Chrome avoids flaky apt mirror dependency downloads.
 // Still perform the full real browser smoke; never replace it with a mock or skip.
 const channel=process.env.BROWSER_E2E_CHROME_CHANNEL==='chrome'?'chrome':undefined;
 browserInstance=await chromium.launch({headless:true,...(channel?{channel}:{})});
 const context=await browserInstance.newContext({baseURL:base});
 // Abort any off-host request; no internet, provider dispatch or tracking during UI smoke.
 await context.route('**/*',route=>{
  const url=route.request().url();
  if(url.startsWith(base+'/')||url===base||url.startsWith('data:')||
     url.startsWith('blob:')||url.startsWith('about:'))return route.continue();
  return route.abort('blockedbyclient');
 });
 const page=await context.newPage();
 await page.goto(base,{waitUntil:'domcontentloaded'});
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 await beginPasswordLogin(page,owner,'Incorrect-browser-test-password');
 await page.getByRole('alert').waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await signIn(page,owner);
 await page.getByRole('button',{name:'Reviewer security'}).waitFor();
 assert.equal(await page.getByRole('heading',{name:'AadiTech · Independent Reviewer'}).count(),0);
 await signOut(page);
 await signIn(page,reviewer);
 await page.getByRole('heading',{name:'AadiTech · Independent Reviewer'}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Reviewer security'}).count(),0);
 const crm=await page.request.get(base+'/api/crm/customers');
 assert.equal(crm.status(),403);
 const drafts=await page.request.get(base+'/api/quotes/drafts');
 assert.equal(drafts.status(),403);
 assert.equal((await page.request.get(base+'/api/security/reviewers')).status(),403);
 const blockedWrite=await page.request.post(base+'/api/crm/customers',{
  data:{},headers:{'Content-Type':'application/json'}
 });
 assert.equal(blockedWrite.status(),403);
 // Simulate reviewer session expiry in the disposable MySQL database. The
 // next page load must land on login; no stale authenticated UI is allowed.
 await db.execute('UPDATE auth_sessions SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE) WHERE user_id=?',
  [reviewer.id]);
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await page.reload({waitUntil:'domcontentloaded'});
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 assert.equal(await page.getByRole('button',{name:'Reviewer security'}).count(),0);
 // Recovery-code sign-in requires a fresh password challenge. Recovery codes
 // are hashed in MySQL and cannot authenticate twice.
 const recovery=randomBytes(10).toString('hex').toUpperCase();
 await db.execute('INSERT INTO auth_totp_recovery_codes (user_id,code_hash) VALUES (?,?)',
  [reviewer.id,hashToken(reviewer.id+':'+recovery)]);
 await beginPasswordLogin(page,reviewer);
 await page.getByRole('heading',{name:'Authenticator verification'}).waitFor();
 // Force the pending challenge to expire; even a correct recovery code must
 // not create a session, and must remain unused for the next valid challenge.
 await db.execute('UPDATE auth_mfa_challenges SET expires_at=DATE_SUB(UTC_TIMESTAMP(3),INTERVAL 1 MINUTE) WHERE user_id=?',
  [reviewer.id]);
 await page.getByRole('textbox',{name:'Authenticator or recovery code'}).fill(recovery);
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByRole('alert').waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await page.getByRole('button',{name:'Cancel and sign in again'}).click();
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 await beginPasswordLogin(page,reviewer);
 await page.getByRole('heading',{name:'Authenticator verification'}).waitFor();
 await page.getByRole('textbox',{name:'Authenticator or recovery code'}).fill(recovery);
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByText('Signed in: '+reviewer.email+' · REVIEWER').waitFor();
 // Reproduce owner-admin disable semantics in this synthetic fixture:
 // status change AND revocation are one transaction. A direct status flip alone
 // is not the supported account-lifecycle operation.
 const disableTx=await db.getConnection();
 try{
  await disableTx.beginTransaction();
  await disableTx.execute("UPDATE auth_users SET status='DISABLED' WHERE id=? AND role='REVIEWER'",[reviewer.id]);
  await disableTx.execute('DELETE FROM auth_sessions WHERE user_id=?',[reviewer.id]);
  await disableTx.commit();
 }catch(e){await disableTx.rollback();throw e;}finally{disableTx.release();}
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await page.reload({waitUntil:'domcontentloaded'});
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 await beginPasswordLogin(page,reviewer);
 await page.getByRole('alert').waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 // Reactivation does not reinstate existing sessions or restore used codes.
 await db.execute("UPDATE auth_users SET status='ACTIVE' WHERE id=? AND role='REVIEWER'",[reviewer.id]);
 await page.reload({waitUntil:'domcontentloaded'});
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await beginPasswordLogin(page,reviewer);
 await page.getByRole('heading',{name:'Authenticator verification'}).waitFor();
 await page.getByRole('textbox',{name:'Authenticator or recovery code'}).fill(recovery);
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByRole('alert').waitFor();
 assert.equal((await page.request.get(base+'/api/auth/me')).status(),401);
 await page.getByRole('button',{name:'Cancel and sign in again'}).click();
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 await context.close();
 console.log('Chromium UI smoke passed: password denial, OWNER/REVIEWER TOTP, recovery one-use, roles and logout');
}finally{
 if(browserInstance)await browserInstance.close();
 // All synthetic credentials are disposed with CI database; do not print secrets.
 await db.end();
}
