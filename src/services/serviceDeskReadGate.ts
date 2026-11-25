// Phase 1FZ: response ownership for read-only service desk lanes.
// A request token is valid only while it is the latest in its lane.
// Invalidation also prevents stale catch/finally handlers from changing
// the loading/error state of a newer request. Not an authorization layer.
export type ServiceDeskReadLane='list'|'detail'|'history'|'fingerprint';
export function createServiceDeskReadGate(){
 const current=new Map<ServiceDeskReadLane,object>();
 return {
  begin(lane:ServiceDeskReadLane){
   const token={};
   current.set(lane,token);
   return ()=>current.get(lane)===token;
  },
  invalidate(...lanes:ServiceDeskReadLane[]){
   for(const lane of lanes)current.delete(lane);
  },
  invalidateAll(){current.clear();}
 };
}
