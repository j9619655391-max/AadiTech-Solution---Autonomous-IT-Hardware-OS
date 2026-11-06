// Phase 1P: real Chromium UI journey on synthetic isolated MySQL; never connect to a deployment.
import assert from 'node:assert/strict';
import {randomUUID} from 'node:crypto';
import {chromium} from 'playwright';
import {getPool} from '../server/db.ts';
import {hashPassword} from '../server/auth/crypto.ts';
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
async function signIn(page,user){
 await page.getByLabel('Work email').fill(user.email);
 await page.getByLabel('Password',{exact:true}).fill(password);
 await page.getByRole('button',{name:'Sign in',exact:true}).click();
 await page.getByRole('heading',{name:'Authenticator verification'}).waitFor();
 // An MFA challenge is not an authenticated session.
 const pending=await page.request.get(base+'/api/auth/me');
 assert.equal(pending.status(),401);
 const code=totpAt(user.secret,Math.floor(Date.now()/30000));
 await page.getByRole('textbox',{name:'Authenticator or recovery code'}).fill(code);
 await page.getByRole('button',{name:'Verify and sign in'}).click();
 await page.getByText('Signed in: '+user.email+' · '+user.role).waitFor();
 const active=await page.request.get(base+'/api/auth/me');
 assert.equal(active.status(),200);
 const data=await active.json();
 assert.equal(data.user.role,user.role);
 return data;
}
async function signOut(page){
 await page.getByRole('button',{name:'Sign out',exact:true}).click();
 await page.getByRole('heading',{name:'AadiTech Solution'}).waitFor();
 const loggedOut=await page.request.get(base+'/api/auth/me');
 assert.equal(loggedOut.status(),401);
}

try{
 const owner=await createUser('OWNER'),reviewer=await createUser('REVIEWER');
 browserInstance=await chromium.launch({headless:true});
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
 await signOut(page);
 await context.close();
 console.log('Chromium UI smoke passed: owner/reviewer MFA, role isolation and logout (synthetic CI only)');
}finally{
 if(browserInstance)await browserInstance.close();
 // All synthetic credentials are disposed with CI database; do not print secrets.
 await db.end();
}
