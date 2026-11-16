import {constants,openSync,closeSync,readSync,lstatSync,fstatSync,realpathSync} from 'node:fs';
import {isAbsolute,resolve,dirname,relative,sep} from 'node:path';
import {fileURLToPath} from 'node:url';
import {TextDecoder} from 'node:util';
import {assessPhase1AuPolicyDrift} from './lib/phase1AuPolicyDrift.mjs';

const CHECKOUT=realpathSync(fileURLToPath(new URL('../',import.meta.url)));
const DECODER=new TextDecoder('utf-8',{fatal:true});
const MAX_BYTES=128*1024;
function inside(root,p){
  const r=relative(root,p);
  return r===''||(!isAbsolute(r)&&r!=='..'&&!r.startsWith('..'+sep));
}
function readPrivateSnapshot(path){
  if(typeof path!=='string'||!isAbsolute(path))throw Error('Absolute private file required');
  const target=resolve(path);
  if(target!==path||realpathSync(target)!==target||inside(CHECKOUT,target))
    throw Error('Evidence path outside approved scope');
  const dir=dirname(target),d=lstatSync(dir);
  if(realpathSync(dir)!==dir||!d.isDirectory()||d.isSymbolicLink()||
     (d.mode&0o077)!==0||
     (typeof process.getuid==='function'&&d.uid!==process.getuid()))
    throw Error('Private review directory required');
  if(!Number.isInteger(constants.O_NOFOLLOW)||!Number.isInteger(constants.O_NONBLOCK))
    throw Error('Secure private evidence opening unsupported');
  const before=lstatSync(target);
  if(!before.isFile()||before.isSymbolicLink()||before.nlink!==1)
    throw Error('Regular private snapshot required');
  const fd=openSync(target,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
  try{
    const stat=fstatSync(fd);
    if(!stat.isFile()||stat.dev!==before.dev||stat.ino!==before.ino||
       stat.nlink!==1||stat.size<1||stat.size>MAX_BYTES||
       (stat.mode&0o077)!==0||
       (typeof process.getuid==='function'&&stat.uid!==process.getuid()))
      throw Error('Private snapshot owner, size or mode rejected');
    const buf=Buffer.alloc(stat.size+1);
    let length=0;
    while(length<buf.length){
      const n=readSync(fd,buf,length,buf.length-length,length);
      if(!n)break;
      length+=n;
    }
    const after=fstatSync(fd);
    if(length!==stat.size||after.size!==stat.size||
       after.mtimeMs!==stat.mtimeMs||after.ctimeMs!==stat.ctimeMs)
      throw Error('Private snapshot changed during read');
    return JSON.parse(DECODER.decode(buf.subarray(0,length)));
  }finally{closeSync(fd);}
}
try{
  const args=process.argv.slice(2),env=process.env;
  if(args.length===1&&args[0]==='--ci-hold'){
    process.stdout.write(JSON.stringify(assessPhase1AuPolicyDrift(),null,2)+'\n');
  }else{
    if(args.length!==3||args[0]!=='--offline-pair'||
       env.PHASE_1AU_OFFLINE_REVIEW_APPROVED!=='YES'||
       env.CI==='true'||env.GITHUB_ACTIONS==='true'||env.NODE_ENV==='production')
      throw Error('Private offline review is not permitted');
    const [oldPath,newPath]=args.slice(1);
    if(!isAbsolute(oldPath)||!isAbsolute(newPath)||
       resolve(oldPath)===resolve(newPath)||
       dirname(resolve(oldPath))!==dirname(resolve(newPath)))
      throw Error('Distinct snapshots in one private directory required');
    const report=assessPhase1AuPolicyDrift(
      readPrivateSnapshot(oldPath),readPrivateSnapshot(newPath)
    );
    // NEVER return success for a private SHA-only policy review, irrespective
    // of a clean-looking diff. No real external source was authenticated.
    process.stdout.write(JSON.stringify(report,null,2)+'\n');
    process.exitCode=2;
  }
}catch{
  process.stderr.write(
    'Phase 1AU HOLD: unsafe or unauthorized policy snapshot; private input withheld.\n'
  );
  process.exitCode=2;
}
