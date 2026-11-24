import {Router} from 'express';
import {requireOwner} from '../auth/router';
import {evaluateInternalPlan,GU_MODULES} from './planners';
import {PlanningInputError} from './validation';
const router=Router();
router.use((_req,res,next)=>{res.setHeader('Cache-Control','no-store');next();});
router.use(requireOwner);
router.get('/',(_req,res)=>{res.json({modules:GU_MODULES,releaseDecision:'HOLD',productionReleaseAuthorized:false,externalExecutionEnabled:false});});
router.post('/:module',(req,res)=>{
 try{res.json(evaluateInternalPlan(req.params.module,req.body));}
 catch(error){if(error instanceof PlanningInputError){res.status(400).json({error:error.code});return;}res.status(503).json({error:'Internal planning unavailable'});}
});
export default router;
