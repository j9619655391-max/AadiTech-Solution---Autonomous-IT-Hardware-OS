import 'dotenv/config';
import mysql from 'mysql2/promise';
import {getDatabaseConfig} from '../server/db';
import {checkPreflightTarget,runStagingPreflight} from './lib/stagingPreflight';

async function main(){
 const target=checkPreflightTarget(process.env);
 const cfg=getDatabaseConfig();
 if(!cfg.database||!cfg.host||!cfg.user||!cfg.password)
  throw Error('Complete database connection settings are required');
 const connection= mysql.createPool({...cfg,connectionLimit:1});
 try{
  const result=await runStagingPreflight(connection,process.env);
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
  if(!result.ready)process.exitCode=1;
  if(target!==result.target)throw Error('Target changed during preflight');
 }finally{await connection.end();}
}
main().catch(e=>{console.error('Preflight refused:',e instanceof Error?e.message:'Unknown');process.exitCode=1;});
