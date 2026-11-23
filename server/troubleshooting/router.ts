import {Router} from 'express';
import {requireAuthenticated} from '../auth/router';
import {searchTroubleGuides,troubleGuideById,validateTroubleSearch,TroubleQueryError} from './guides';

// Internal static knowledge-base only. No device scanning, command execution,
// operating-system privileges, local uploads or customer service ticket writes.
const router=Router();
router.use((_req,res,next)=>{
 res.setHeader('Cache-Control','no-store');
 res.setHeader('X-Content-Type-Options','nosniff');
 next();
});
router.use(requireAuthenticated);
router.get('/',(req,res)=>{
 try{
  const {query,category}=validateTroubleSearch(req.query.q,req.query.category);
  const items=searchTroubleGuides(query,category);
  res.json({mode:'GUIDANCE_ONLY',deviceInspected:false,actionsExecuted:false,
   total:items.length,items});
 }catch(e){
  if(e instanceof TroubleQueryError){res.status(400).json({error:e.message});return;}
  res.status(503).json({error:'Troubleshooting catalog unavailable'});
 }
});
router.get('/:id',(req,res)=>{
 const item=troubleGuideById(req.params.id);
 if(!item){res.status(404).json({error:'Guide not found'});return;}
 res.json({mode:'GUIDANCE_ONLY',deviceInspected:false,actionsExecuted:false,item});
});
export default router;
