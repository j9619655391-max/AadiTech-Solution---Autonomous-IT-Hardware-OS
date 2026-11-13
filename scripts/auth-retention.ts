import 'dotenv/config';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {assertSafeRetentionEnvironment,runRetention} from './lib/authRetention';

async function main(){
 const args=process.argv.slice(2);
 const apply=args.includes('--apply');
 if(args.some(x=>x!=='--apply'))
  throw Error('Supported option: --apply (disposable test database ONLY)');
 assertSafeRetentionEnvironment(process.env,apply);
 const config=getDatabaseConfig();
 if(!config.host||!config.database||!config.password||!config.user)
  throw Error('Missing MySQL configuration');
 const db=mysql.createPool({...config,connectionLimit:1});
 try{
  const report=await runRetention(db,process.env,apply);
  process.stdout.write(JSON.stringify(report,null,2)+'\n');
 }finally{await db.end();}
}
main().catch(e=>{console.error('Retention refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
