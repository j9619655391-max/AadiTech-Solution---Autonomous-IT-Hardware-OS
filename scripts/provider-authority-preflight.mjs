import {readFileSync,lstatSync} from 'node:fs';
import {resolve,relative,isAbsolute,sep} from 'node:path';
import {reviewPhase1ApDigestInventory} from './lib/providerAuthorityPreflight.mjs';

function inspect(argv,env){
 if(argv.length===0||(argv.length===1&&argv[0]==='--ci-hold'))
  return reviewPhase1ApDigestInventory(null);
 if(argv.length!==2||argv[0]!=='--offline-packet')
  throw Error('Offline SHA-only review requires explicit private packet');
 if(env.GITHUB_ACTIONS==='true'||env.NODE_ENV==='production'||
    env.PHASE_1AP_OFFLINE_INSPECTION_APPROVED!=='YES')
  throw Error('Offline intake prohibited in CI/production or without operator permission');
 if(!isAbsolute(argv[1]))throw Error('Private packet path must be absolute');
 const p=resolve(argv[1]),relativePath=relative(process.cwd(),p);
 if(!relativePath||relativePath==='..'||
    (!relativePath.startsWith('..'+sep)&&!isAbsolute(relativePath)))
  throw Error('Private packet must remain outside Git repository');
 const stat=lstatSync(p);
 if(!stat.isFile()||stat.isSymbolicLink()||stat.size===0||stat.size>16384)
  throw Error('Private packet must be a small regular SHA-only file');
 return reviewPhase1ApDigestInventory(JSON.parse(readFileSync(p,'utf8')));
}
try{
 const report=inspect(process.argv.slice(2),process.env);
 // Never echo the manifest, its fingerprints, source path or any credentials.
 process.stdout.write(JSON.stringify(report,null,2)+'\n');
}catch(_error){
 process.stderr.write('Phase 1AP HOLD: invalid or unauthorized digest inventory; input and path withheld.\n');
 process.exitCode=2;
}
