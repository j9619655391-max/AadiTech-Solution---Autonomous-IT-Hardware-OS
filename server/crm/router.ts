import { Router, type Request, type Response } from 'express';
import { getPool } from '../db';
import { MySQLCRMRepository, type CRMRepository, validId } from './repository';
import { InputError, parsePagination, parseVersion, validate, type CRMEntity } from './validation';
import { requireOwner } from '../auth/router';

const names = new Set<CRMEntity>(['customers','leads','products']);
function entityFrom(value: unknown): CRMEntity {
  if(typeof value !== 'string' || !names.has(value as CRMEntity)) throw new InputError('Unknown resource');
  return value as CRMEntity;
}
type Provider = () => CRMRepository | null;
function defaultProvider(): CRMRepository | null {
  const pool=getPool();
  return pool ? new MySQLCRMRepository(pool) : null;
}
function error(res:Response,e:unknown) {
  if (e instanceof InputError) {res.status(400).json({error:e.message});return;}
  if(e && typeof e==='object' && 'code' in e && (e.code==='ER_DUP_ENTRY')) {res.status(409).json({error:'Duplicate record'});return;}
  // Do not leak SQL or database credentials in response bodies.
  console.error('CRM request failed:',e instanceof Error?e.name:'Unknown error');
  res.status(503).json({error:'CRM service unavailable'});
}
export function createCRMRouter(provider:Provider=defaultProvider) {
  const router=Router();
  router.use(requireOwner);
  router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});

  router.get('/:entity',async(req,res)=>{
    try {
      const entity=entityFrom(req.params.entity);
      const {limit,offset,page}=parsePagination(req.query);
      const repo=provider();
      if(!repo){res.status(503).json({error:'CRM service unavailable'});return;}
      const result=await repo.list(entity,limit,offset);
      res.json({...result,page,limit});
    }catch(e){error(res,e);}
  });
  router.get('/:entity/:id',async(req,res)=>{
    try{
      const entity=entityFrom(req.params.entity);
      if(!validId(req.params.id))throw new InputError('Invalid ID');
      const repo=provider();
      if(!repo){res.status(503).json({error:'CRM service unavailable'});return;}
      const item=await repo.get(entity,req.params.id);
      if(!item){res.status(404).json({error:'Record not found'});return;}
      res.json(item);
    }catch(e){error(res,e);}
  });
  router.post('/:entity',async(req,res)=>{
    try{
      const entity=entityFrom(req.params.entity),fields=validate(entity,req.body);
      const repo=provider();
      if(!repo){res.status(503).json({error:'CRM service unavailable'});return;}
      const result=await repo.create(entity,fields,res.locals.auth.userId);
      res.status(201).json(result);
    }catch(e){error(res,e);}
  });
  router.patch('/:entity/:id',async(req,res)=>{
    try{
      const entity=entityFrom(req.params.entity);
      if(!validId(req.params.id))throw new InputError('Invalid ID');
      const {expectedVersion,...raw}=req.body || {};
      const version=parseVersion(expectedVersion), fields=validate(entity,raw,true);
      const repo=provider();
      if(!repo){res.status(503).json({error:'CRM service unavailable'});return;}
      const result=await repo.update(entity,req.params.id,version,fields,res.locals.auth.userId);
      if(result==='not_found'){res.status(404).json({error:'Record not found'});return;}
      if(result==='conflict'){res.status(409).json({error:'Record changed; refresh and retry'});return;}
      res.json(result);
    }catch(e){error(res,e);}
  });
  router.delete('/:entity/:id',async(req,res)=>{
    try{
      const entity=entityFrom(req.params.entity);
      if(!validId(req.params.id))throw new InputError('Invalid ID');
      const version=parseVersion(req.header('if-match'));
      const repo=provider();
      if(!repo){res.status(503).json({error:'CRM service unavailable'});return;}
      const result=await repo.remove(entity,req.params.id,version,res.locals.auth.userId);
      if(result==='not_found'){res.status(404).json({error:'Record not found'});return;}
      if(result==='conflict'){res.status(409).json({error:'Record changed; refresh and retry'});return;}
      res.status(204).end();
    }catch(e){error(res,e);}
  });
  return router;
}
export default createCRMRouter();
