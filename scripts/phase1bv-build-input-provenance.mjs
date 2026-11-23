import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {readBunLock} from './phase1bt-production-scope.mjs';

// Phase 1BV is a *local CI build-input integrity and execution-boundary
// inventory*, not a signed SLSA provenance, external independent witness,
// patched picomatch, vulnerability waiver or release authorization.
export const BUILD_INPUT_PATHS=Object.freeze([
 '.github/workflows/ci.yml',
 'bun.lock',
 'docs/security/phase1cm-main-ruleset-PROPOSAL-UNAPPLIED.json',
 'index.html',
 'package.json',
 'scripts/phase1bt-production-scope.mjs',
 'scripts/phase1bv-build-input-provenance.mjs',
 'scripts/phase1bz-actions-pin-preflight.mjs',
 'scripts/phase1cb-public-advisory-observer.mjs',
 'scripts/phase1ch-upstream-patch-publication-preflight.mjs',
 'scripts/phase1cj-advisory-withdrawal-quarantine.mjs',
 'scripts/phase1ck-picomatch-bounded-adjudication.mjs',
 'scripts/phase1cl-live-codeowners-reviewer-onboarding.mjs',
 'scripts/phase1cm-admin-ruleset-reviewer-handoff.mjs',
 'scripts/phase1cn-ruleset-bypass-reconciliation.mjs',
 'scripts/phase1co-live-exact-head-reviewer-quorum.mjs',
 'scripts/phase1cp-github-actions-check-app-source.mjs',
 'scripts/phase1cq-postrun-github-check-receipt.mjs',
 'scripts/phase1cr-actions-jobs-reconciliation.mjs',
 'scripts/phase1ct-dual-event-postrun-governance.mjs',
 'scripts/phase1cu-independent-governance-handoff.mjs',
 'scripts/phase1cv-policy-freeze-detached-candidate.mjs',
 'scripts/phase1cw-crossrun-revocation-recovery-candidate.mjs',
 'scripts/phase1cx-pinned-external-source-highwatermark.mjs',
 'scripts/phase1cy-operator-pin-lifecycle-quarantine.mjs',
 'scripts/phase1cz-corporate-mandate-incident-quarantine.mjs',
 'scripts/phase1da-appendonly-incident-replay-ledger.mjs',
 'scripts/phase1db-external-mandate-cas-sealed-recovery.mjs',
 'scripts/phase1dc-live-external-governance-readiness.mjs',
 'scripts/phase1dd-authorized-human-handoff.mjs',
 'scripts/phase1de-admin-activation-readiness.mjs',
 'scripts/phase1df-role-bound-readonly-reconciliation.mjs',
 'scripts/phase1dg-effective-codeowners.mjs',
 'scripts/phase1di-terminal-main-review-recheck.mjs',
 'scripts/phase1dk-submitted-review-history-integrity.mjs',
 'scripts/phase1dl-ephemeral-reviewer-handoff-continuity.mjs',
 'scripts/phase1dm-corporate-appointment-challenge-handoff.mjs',
 'scripts/phase1dn-corporate-role-session-reconciliation.mjs',
 'scripts/phase1do-offline-registrar-witness-enrollment.mjs',
 'scripts/phase1dp-offline-registrar-witness-equivocation.mjs',
 'scripts/phase1dr-offline-keyid-bound-witness-v2.mjs',
 'scripts/phase1ds-offline-witness-key-rollover.mjs',
 'scripts/phase1dt-offline-rollover-checkpoint-continuity.mjs',
 'scripts/phase1du-offline-multi-epoch-rollover-chain.mjs',
 'scripts/phase1dv-offline-observer-publication-candidate.mjs',
 'scripts/phase1dw-offline-observer-enrollment-revocation.mjs',
 'scripts/phase1dx-offline-evidence-incident-recovery.mjs',
 'scripts/phase1dy-offline-source-admission-unfreeze-preconditions.mjs',
 'scripts/phase1dz-offline-cross-epoch-anchor-custody.mjs',
 'scripts/phase1ea-offline-gossip-admission-boundary.mjs',
 'scripts/phase1eb-offline-cross-run-gossip-incident-custody.mjs',
 'scripts/phase1ec-offline-authority-handoff-custody.mjs',
 'scripts/phase1ed-disconnected-authority-verification-ports.mjs',
 'scripts/phase1ee-disconnected-version-failure-taxonomy.mjs',
 'scripts/phase1ef-disconnected-quarantine-escalation.mjs',
 'scripts/phase1eg-unsent-manual-authority-handoff.mjs',
 'scripts/phase1eh-disconnected-response-intake-quarantine.mjs',
 'scripts/phase1ei-independent-admission-prerequisites.mjs',
 'scripts/phase1by-github-governance-observer.mjs',
 'scripts/phase1cs-push-head-governance.mjs',
 'scripts/phase1ck-picomatch-worker.cjs',
 'scripts/phase1ci-picomatch-exposure-preflight.mjs',
 'scripts/phase1cc-ci-evidence-envelope.mjs',
 'scripts/phase1cd-external-custody-preflight.mjs',
 'scripts/phase1ce-cross-witness-retrieval-preflight.mjs',
 'scripts/phase1cf-checkpoint-publication-review-preflight.mjs',
 'scripts/phase1cg-external-source-reconciliation-preflight.mjs',
 'scripts/verify-patched-dependencies.mjs',
 'database/migrations/0044_en_workflow_review_scopes.sql',
 'scripts/migrate-en-reviewer-scopes.ts',
 'tests/en-reviewer-scope-migration.test.ts',
 'database/migrations/0045_eo_stock_journal_review_scopes.sql',
 'scripts/migrate-eo-reviewer-scopes.ts',
 'tests/eo-reviewer-scope-migration.test.ts',
 'database/migrations/0046_ep_proof_key_trust_review_scopes.sql',
 'database/migrations/0047_eq_provider_review_scopes.sql',
 'scripts/migrate-eq-provider-scopes.ts',
 'tests/eq-provider-reviewer-scope-migration.test.ts',
 'server/security/providerReviewScope.ts',
 'server/providerBridge/reviewRouter.ts',
 'server/providerSandbox/reviewRouter.ts',
 'server/providerSelection/reviewRouter.ts',
 'server/providerOnboarding/reviewRouter.ts',
 'scripts/migrate-ep-reviewer-scopes.ts',
 'server/security/sensitiveReviewScope.ts',
 'server/proofFoundation/reviewRouter.ts',
 'server/keyLifecycle/reviewRouter.ts',
 'server/externalTrust/reviewRouter.ts',
 'tests/signed-proof-mysql.integration.ts',
 'tests/key-lifecycle-mysql.integration.ts',
 'tests/provider-bridge-mysql.integration.ts',
 'tests/provider-sandbox-mysql.integration.ts',
 'tests/provider-selection-mysql.integration.ts',
 'tests/external-trust-mysql.integration.ts',
 'tests/ep-reviewer-scope-migration.test.ts',
 'server/stockFoundation/reviewRouter.ts',
 'server/journalFoundation/reviewRouter.ts',
 'tests/stock-foundation-mysql.integration.ts',
 'tests/journal-foundation-mysql.integration.ts',
 'server/intake/reviewRouter.ts',
 'server/dispatch/reviewRouter.ts',
 'server/evidenceChain/reviewRouter.ts',
 'tests/dispatch-mysql.integration.ts',
 'tests/evidence-chain-mysql.integration.ts',
 'server/intake/ownerRouter.ts',
 'tests/intake-mysql.integration.ts',
 'server/inventory/router.ts',
 'tests/inventory-mysql.integration.ts',
 'server/crm/repository.ts',
 'server/crm/router.ts',
 'server/quotes/router.ts',
 'server/procurement/ownerRouter.ts',
 'tests/staging-preflight.test.ts',
 'tests/el-reviewer-scope-migration.test.ts',
 'tests/crm-mysql.integration.ts',
 'tests/fa-role-cycle-concurrency-mysql.integration.ts',
 'tests/fb-runtime-db-privileges.test.ts',
 'tests/fc-runtime-db-privileges-mysql.integration.ts',
 'tests/fd-crm-owner-race-mysql.integration.ts',
 'tests/procurement-mysql.integration.ts',
 'database/migrations/0043_el_reviewer_scope_candidates.sql',
 'scripts/migrate-el-reviewer-scopes.ts',
 'server/security/reviewerScopeRouter.ts',
 'server/quotes/reviewRouter.ts',
 'tests/er-legacy-reviewer-active-identity.test.mjs',
 'tests/es-reviewer-nominator-transaction.test.mjs',
 'tests/et-reviewer-lifecycle.test.mjs',
 'scripts/migrate-ew-role-cycle.ts',
 'tests/ex-trigger-body-integrity.test.ts',
 'server/security/adminRouter.ts',
 'server/procurement/reviewRouter.ts',
 'scripts/lib/stagingPreflight.ts',
 'scripts/staging-preflight.ts',
 'scripts/phase1fb-runtime-db-privileges.ts',
 'server.ts',
 'server/security/deploymentGuards.ts',
 'server/security/devToolExposure.ts',
 'tsconfig.json',
 'tests/phase1bv-build-input-provenance.test.mjs',
 'tests/phase1bz-actions-pin.test.mjs',
 'tests/phase1cb-public-advisory-observer.test.mjs',
 'tests/phase1ch-upstream-patch-publication-preflight.test.mjs',
 'tests/phase1cj-advisory-withdrawal-quarantine.test.mjs',
 'tests/phase1ck-picomatch-bounded-adjudication.test.mjs',
 'tests/phase1cl-live-codeowners-reviewer-onboarding.test.mjs',
 'tests/phase1cm-admin-ruleset-reviewer-handoff.test.mjs',
 'tests/phase1cn-ruleset-bypass-reconciliation.test.mjs',
 'tests/phase1co-live-exact-head-reviewer-quorum.test.mjs',
 'tests/phase1cp-github-actions-check-app-source.test.mjs',
 'tests/phase1cq-postrun-github-check-receipt.test.mjs',
 'tests/phase1cr-actions-jobs-reconciliation.test.mjs',
 'tests/phase1ct-dual-event-postrun-governance.test.mjs',
 'tests/phase1cu-independent-governance-handoff.test.mjs',
 'tests/phase1cv-policy-freeze-detached-candidate.test.mjs',
 'tests/phase1cw-crossrun-revocation-recovery-candidate.test.mjs',
 'tests/phase1cx-pinned-external-source-highwatermark.test.mjs',
 'tests/phase1cy-operator-pin-lifecycle-quarantine.test.mjs',
 'tests/phase1cz-corporate-mandate-incident-quarantine.test.mjs',
 'tests/phase1da-appendonly-incident-replay-ledger.test.mjs',
 'tests/phase1db-external-mandate-cas-sealed-recovery.test.mjs',
 'tests/phase1dc-live-external-governance-readiness.test.mjs',
 'tests/phase1dd-authorized-human-handoff.test.mjs',
 'tests/phase1de-admin-activation-readiness.test.mjs',
 'tests/phase1df-role-bound-readonly-reconciliation.test.mjs',
 'tests/phase1dg-effective-codeowners.test.mjs',
 'tests/phase1dh-codeowners-contract.test.mjs',
 'tests/phase1di-terminal-main-review-recheck.test.mjs',
 'tests/phase1dk-submitted-review-history-integrity.test.mjs',
 'tests/phase1dl-ephemeral-reviewer-handoff-continuity.test.mjs',
 'tests/phase1dm-corporate-appointment-challenge-handoff.test.mjs',
 'tests/phase1dn-corporate-role-session-reconciliation.test.mjs',
 'tests/phase1do-offline-registrar-witness-enrollment.test.mjs',
 'tests/phase1dp-offline-registrar-witness-equivocation.test.mjs',
 'tests/phase1dr-offline-keyid-bound-witness-v2.test.mjs',
 'tests/phase1ds-offline-witness-key-rollover.test.mjs',
 'tests/phase1dt-offline-rollover-checkpoint-continuity.test.mjs',
 'tests/phase1by-github-governance-observer.test.mjs',
 'tests/phase1dj-bounded-github-pr-observer.test.mjs',
 'tests/helpers/phase1cz-candidate-fixture.mjs',
 'tests/helpers/phase1da-candidate-fixture.mjs',
 'tests/helpers/phase1db-candidate-fixture.mjs',
 'tests/phase1cs-push-head-governance.test.mjs',
 'tests/phase1ci-picomatch-exposure-preflight.test.mjs',
 'tests/phase1cc-ci-evidence-envelope.test.mjs',
 'tests/phase1cd-external-custody-preflight.test.mjs',
 'tests/phase1ce-cross-witness-retrieval-preflight.test.mjs',
 'tests/phase1cf-checkpoint-publication-review-preflight.test.mjs',
 'tests/phase1cg-external-source-reconciliation-preflight.test.mjs',
 'vite.config.ts'
]);
const EXACT_SCRIPTS=Object.freeze({
 dev:'tsx server.ts',
 start:'node dist/server.cjs',
 build:'vite build && esbuild server.ts --bundle --platform=node --format=cjs --packages=external --sourcemap --outfile=dist/server.cjs',
 lint:'tsc --noEmit',
 test:'node --test tests/*.test.mjs && tsx --test tests/*.test.ts'
});
const FORBIDDEN_LIFECYCLE=Object.freeze([
 'preinstall','install','postinstall','prepare','prepack','postpack',
 'prepublish','prepublishOnly','predev','postdev','prebuild','postbuild',
 'pretest','posttest','prestart','poststart'
]);
const sha256=s=>createHash('sha256').update(s).digest('hex');
const DOMAIN='aaditech/ci/build-input-provenance/v1\n';
const SCAN=/\b(?:import\.meta\.glob|fast-glob|micromatch|picomatch|globSync|globStream)\b|(?:glob(?:Pattern|Input|Source|Entry|Entries)|optimizeDeps\.entries|rollupOptions\.input)\s*[:=]/;
function present(source,rx){return rx.test(source);}
export function assessBuildInputBoundary({pkg,lock,server,vite,ci,devExposure,environment={}}){
 const anomalies=new Set();
 if(!pkg||!lock||typeof server!=='string'||typeof vite!=='string'||
    typeof ci!=='string'||typeof devExposure!=='string')
  throw Error('BV build boundary requires all exact source inputs');
 const scripts=pkg.scripts;
 if(!scripts||typeof scripts!=='object'||Array.isArray(scripts))
  anomalies.add('BV_PACKAGE_SCRIPTS_MALFORMED');
 else{
  for(const [key,value] of Object.entries(EXACT_SCRIPTS)){
   if(scripts[key]!==value)anomalies.add('BV_UNREVIEWED_EXECUTABLE_SCRIPT_'+key);
  }
  for(const key of FORBIDDEN_LIFECYCLE)
   if(Object.hasOwn(scripts,key))anomalies.add('BV_INSTALL_OR_BUILD_LIFECYCLE_SCRIPT_'+key);
  for(const [name,command] of Object.entries(scripts)){
   if(typeof command!=='string'||command.length>512||/[\r\n\0]/.test(command))
    anomalies.add('BV_MALFORMED_SCRIPT_'+name);
  }
 }
 if(Object.hasOwn(pkg,'trustedDependencies')&&
    (!Array.isArray(pkg.trustedDependencies)||pkg.trustedDependencies.length))
  anomalies.add('BV_UNREVIEWED_BUN_TRUSTED_INSTALL_SCRIPTS');
 if(pkg.workspaces||pkg.patchedDependencies)
  anomalies.add('BV_UNREVIEWED_WORKSPACES_OR_PATCHES');
 const workspace=lock.workspaces?.[''];
 if(!workspace||!lock.packages||
    workspace.dependencies?.vite!==undefined||
    workspace.devDependencies?.vite!=='6.4.5'||
    lock.packages.picomatch?.[0]!=='picomatch@4.0.7')
  anomalies.add('BV_BUILD_DEPENDENCY_GRAPH_UNEXPECTED');
 if(!present(server,/process\.env\.NODE_ENV\s*!==\s*["']production["']\s*\)\s*\{[\s\S]{0,300}await import\(["']vite["']\)/))
  anomalies.add('BV_VITE_IMPORT_PRODUCTION_BOUNDARY_CHANGED');
 if(!present(server,/app\.use\(devToolHostGate\(devExposure\)\)/))
  anomalies.add('BV_DEV_HTTP_GATE_MISSING');
 if(!present(server,/host:\s*'127\.0\.0\.1'/)||
    !present(server,/hmr:\s*false/)||
    !present(server,/cors:\s*false/))
  anomalies.add('BV_VITE_MIDDLEWARE_UNRESTRICTED');
 if(!present(devExposure,/devToolHostGate/)||
    !present(devExposure,/APP_ALLOW_PUBLIC_BIND/)||
    !present(devExposure,/Local-only developer tooling request denied/))
  anomalies.add('BV_DEV_TOOL_BOUNDARY_MISSING');
 if(!present(vite,/plugins:\s*\[react\(\),\s*tailwindcss\(\)\]/)||
    !present(vite,/import react from '@vitejs\/plugin-react'/)||
    !present(vite,/import tailwindcss from '@tailwindcss\/vite'/))
  anomalies.add('BV_VITE_UNREVIEWED_PLUGIN_CHAIN');
 // A comment mentioning a vulnerability is not executable glob input.
 // This is an intentionally bounded configuration heuristic, not a parser or
 // a full repository-wide dataflow / regex exploitability proof.
 const viteCode=vite.replace(/^\s*\/\/[^\n]*$/gm,'');
 if(SCAN.test(viteCode))
  anomalies.add('BV_DYNAMIC_GLOB_OR_BUILD_INPUT_DISCOVERY');
 // Verify dev and preview independently: a permissive server must never
 // be accepted merely because preview still has a restrictive cors setting.
 const serverBlock=viteCode.match(/server:\s*\{([\s\S]*?)\n\s*\},\s*\n\s*preview:/)?.[1]??'';
 const previewBlock=viteCode.match(/preview:\s*\{([\s\S]*?)\n\s*\},/)?.[1]??'';
 for(const block of [serverBlock,previewBlock]){
  if(!present(block,/host:\s*'127\.0\.0\.1'/)||
     !present(block,/allowedHosts:\s*\['localhost','127\.0\.0\.1'\]/)||
     !present(block,/strictPort:\s*true/)||
     !present(block,/cors:\s*false/))
   anomalies.add('BV_VITE_LOCAL_ONLY_CONSTRAINT_DRIFT');
 }
 if(!present(serverBlock,/fs:\s*\{strict:\s*true\}/)||
    !present(serverBlock,/hmr:\s*false/))
  anomalies.add('BV_VITE_LOCAL_ONLY_CONSTRAINT_DRIFT');
 if(!present(ci,/^on:\s*\n\s*push:\s*\n\s*pull_request:\s*$/m)||
    present(ci,/pull_request_target:|workflow_run:|repository_dispatch:|workflow_dispatch:/))
  anomalies.add('BV_UNREVIEWED_CI_ENTRYPOINT');
 if(!present(ci,/^permissions:\s*\n\s*contents:\s*read\s*$/m)||
    present(ci,/^\s*(?:id-token|packages|actions|contents|security-events):\s*write\s*$/m))
  anomalies.add('BV_CI_TOKEN_PERMISSION_ESCALATION');
 if(!present(ci,/^  baseline:\s*\n    runs-on: ubuntu-24\.04/m)||
    !present(ci,/^  mysql-integration:\s*\n    runs-on: ubuntu-24\.04/m)||
    !present(ci,/^  production-runtime-scope:\s*\n    runs-on: ubuntu-24\.04/m))
  anomalies.add('BV_NON_GITHUB_HOSTED_RUNNER_OR_JOB_REMOVED');
 if(!present(ci,/bun install --frozen-lockfile/)||
    !present(ci,/bun install --frozen-lockfile --production/)||
    !present(ci,/Verify patched dependency versions and zero critical\/high advisory matches/)||
    !present(ci,/node scripts\/verify-patched-dependencies\.mjs/))
  anomalies.add('BV_FROZEN_INSTALL_OR_HIGH_RISK_GATE_REMOVED');
 if(!present(ci,/BROWSER_E2E_BASE_URL: 'http:\/\/127\.0\.0\.1:3000'/)||
    !present(ci,/node --import tsx scripts\/browser-smoke\.mjs/)||
    !present(ci,/APP_PID=\$!/)||
    !present(ci,/trap 'kill "\$APP_PID" 2>\/dev\/null \|\| true' EXIT/))
  anomalies.add('BV_CI_BROWSER_LOOPBACK_AND_CLEANUP_CHANGED');
 if(/^\s*(?:secrets|environment):/m.test(ci)||
    present(ci,/^\s*uses:\s*docker:\/\//m))
  anomalies.add('BV_CI_SECRET_OR_REMOTE_EXECUTION_ENTRYPOINT');
 if(environment.CI==='true'||environment.GITHUB_ACTIONS==='true'){
  if(environment.GITHUB_REPOSITORY!==
      'j9619655391-max/AadiTech-Solution---Autonomous-IT-Hardware-OS')
   anomalies.add('BV_UNEXPECTED_CI_REPOSITORY');
  if(!/^[0-9a-f]{40}$/.test(environment.GITHUB_SHA??''))
   anomalies.add('BV_INVALID_CI_COMMIT_SHA');
  if(!/^refs\/heads\/chore\/phase0-foundation-20261106$|^refs\/pull\/\d+\/merge$/.test(
      environment.GITHUB_REF??''))
   anomalies.add('BV_UNREVIEWED_CI_REF');
 }
 return Object.freeze({
  schemaVersion:1,phase:'1BV',
  localBuildInputBoundaryConsistent:anomalies.size===0,
  anomalyCodes:Object.freeze([...anomalies].sort()),
  reviewedBuildEntryPoints:Object.keys(EXACT_SCRIPTS).length,
  untrustedGlobPatternAccepted:false,
  externallySignedBuildProvenance:false,
  independentSourceAndReviewerApprovalVerified:false,
  vulnerablePicomatchStillInDevLock:true,
  picomatchCve:'CVE-2026-112366',
  upstreamVendorFixVerified:false,
  independentSecurityApprovalVerified:false,
  criticalHighSecurityGateMayBeBypassed:false,
  productionReleaseAuthorized:false,
  productionReleaseBlocked:true,releaseDecision:'HOLD'
 });
}
export function makeBuildInputInventory(sources,environment={}){
 const anomalies=[];
 const files=[];
 for(const name of BUILD_INPUT_PATHS){
  const value=sources[name];
  if(typeof value!=='string'||value.length<1||Buffer.byteLength(value)>1024*1024)
   anomalies.push('BV_UNREADABLE_OR_OVERSIZED_INPUT_'+name);
  else files.push({path:name,bytes:Buffer.byteLength(value),sha256:sha256(value)});
 }
 if(anomalies.length)throw Error(anomalies.join(','));
 const bundleSha256=sha256(DOMAIN+
   files.map(f=>f.path+'\0'+f.bytes+'\0'+f.sha256+'\n').join(''));
 return Object.freeze({
  schemaVersion:1,kind:'UNSIGNED_LOCAL_CI_INPUT_INVENTORY',
  phase:'1BV',algorithm:'SHA-256',
  claimedGithubSha:/^[0-9a-f]{40}$/.test(environment.GITHUB_SHA??'')?
   environment.GITHUB_SHA:null,
  bundleSha256,
  files:Object.freeze(files),
  signedByIndependentWitness:false,
  verifiedExternalWormRetention:false,
  independentSecurityApprovalVerified:false,
  releaseDecision:'HOLD',
  productionReleaseAuthorized:false
 });
}
function main(){
 const sources={};
 for(const path of BUILD_INPUT_PATHS){
  const info=lstatSync(path);
  if(!info.isFile()||info.isSymbolicLink()||info.size>1024*1024)
   throw Error('BV untrusted source file type/size '+path);
  sources[path]=readFileSync(path,'utf8');
 }
 const pkg=JSON.parse(sources['package.json']);
 const lock=readBunLock(sources['bun.lock']);
 const boundary=assessBuildInputBoundary({
  pkg,lock,server:sources['server.ts'],
  vite:sources['vite.config.ts'],ci:sources['.github/workflows/ci.yml'],
  devExposure:sources['server/security/devToolExposure.ts'],
  environment:process.env
 });
 const inventory=makeBuildInputInventory(sources,process.env);
 const output={boundary,inventory};
 writeFileSync('phase1bv-held-build-input-report.json',
  JSON.stringify(output,null,2)+'\n',{flag:'w',mode:0o600});
 console.log(JSON.stringify(output,null,2));
 if(!boundary.localBuildInputBoundaryConsistent)process.exitCode=1;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{main();}catch(e){
  console.error('Phase 1BV local build-input custody failed:',
    e instanceof Error?e.message:'Unknown');
  process.exitCode=1;
 }
}
