import {validId} from '../crm/repository';
import {ServiceTicketInputError,rejectCredentialLikeTicketText} from '../serviceDesk/validation';

export function validateHeldFieldPlan(body:unknown){
 if(!body||typeof body!=='object'||Array.isArray(body))
  throw new ServiceTicketInputError('Invalid internal field plan');
 const b=body as Record<string,unknown>;
 const allowed=['ticketId','expectedTicketVersion','kind','note','acknowledgeUnverifiedAuthority'];
 if(Object.keys(b).length!==allowed.length||Object.keys(b).some(k=>!allowed.includes(k)))
  throw new ServiceTicketInputError('Unexpected internal field plan fields');
 if(!validId(b.ticketId)||!Number.isSafeInteger(b.expectedTicketVersion)||
    Number(b.expectedTicketVersion)<2||Number(b.expectedTicketVersion)>=1000)
  throw new ServiceTicketInputError('Valid triaged ticket ID and bounded version required');
 if(b.kind!=='WORK_ORDER'&&b.kind!=='RMA')
  throw new ServiceTicketInputError('Invalid internal plan kind');
 if(b.acknowledgeUnverifiedAuthority!==true)
  throw new ServiceTicketInputError('Acknowledge unverified service authority');
 if(typeof b.note!=='string'||!b.note.trim()||b.note.trim().length>500||
    /[\u0000-\u001f\u007f]/.test(b.note))
  throw new ServiceTicketInputError('Invalid internal planning note');
 const note=b.note.trim();rejectCredentialLikeTicketText(note);
 return {ticketId:b.ticketId,expectedTicketVersion:Number(b.expectedTicketVersion),kind:b.kind,note};
}
