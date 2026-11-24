import {Router} from 'express';
import {requireOwner} from '../auth/router';
import {evaluateInternalPlan,GU_MODULES} from './planners';
import {PlanningInputError} from './validation';
import {getPool} from '../db';
import {CRMOwnerInactiveError} from '../crm/repository';
import {gvPersistenceEnabled,gvSessionCookie,gvCreate,gvRead,gvList,PlanningRecordError} from './records';
const router=Router();
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
router.use(requireOwner);
router.get('/',(_req,res)=>{res.json({modules:GU_MODULES,releaseDecision:'HOLD',productionReleaseAuthorized:false,externalExecutionEnabled:false,persistenceEnabled:gvPersistenceEnabled()});});
function recordFailure(res:import('express').Response,e:unknown){
 if(e instanceof PlanningInputError){res.status(400).json({error:e.code});return;}
 if(e instanceof PlanningRecordError){res.status(e.status).json({error:e.code});return;}
 if(e instanceof CRMOwnerInactiveError){res.status(403).json({error:'SESSION_AUTHORITY_REQUIRED'});return;}
 res.status(503).json({error:'Internal planning records unavailable'});
}
function recordPool(){if(!gvPersistenceEnabled())throw new PlanningRecordError(503,'PERSISTENCE_DISABLED');const db=getPool();if(!db)throw new PlanningRecordError(503,'PERSISTENCE_DISABLED');return db;}
router.get('/records',async(req,res)=>{try{res.json(await gvList(recordPool(),res.locals.auth.userId,gvSessionCookie(req.headers.cookie)));}catch(e){recordFailure(res,e);}});
router.get('/records/:id',async(req,res)=>{try{res.json(await gvRead(recordPool(),res.locals.auth.userId,gvSessionCookie(req.headers.cookie),req.params.id));}catch(e){recordFailure(res,e);}});
router.post('/records/:module',async(req,res)=>{try{const v=await gvCreate(recordPool(),res.locals.auth.userId,gvSessionCookie(req.headers.cookie),req.header('idempotency-key'),req.params.module,req.body);res.status(v.replayed?200:201).json(v);}catch(e){recordFailure(res,e);}});
router.post('/:module',(req,res)=>{
 try{res.json(evaluateInternalPlan(req.params.module,req.body));}
 catch(error){if(error instanceof PlanningInputError){res.status(400).json({error:error.code});return;}res.status(503).json({error:'Internal planning unavailable'});}
});
export default router;
