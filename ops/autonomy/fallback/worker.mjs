/* Optional independent schedule canary; requires Safety approval and operator deployment.
 * No public trigger, no source execution, no direct repository writes. */
export const REPO = "LMhdez/gaslux";
const API = "https://api.github.com/repos/" + REPO + "/actions/workflows/";
const SHA = /^[a-f0-9]{40}$/;
const WORKFLOWS = Object.freeze([
  {file:"gaslux-agent-lifecycle-research.yml", stale:45, level:"read-only", inputs:{mint_live_boot:"false"}},
  {file:"gaslux-agent-clock.yml", stale:35, level:"privileged", inputs:{role:"auto"}},
  {file:"gaslux-agent-integrator.yml", stale:35, level:"privileged", inputs:{}},
  {file:"gaslux-agent-feature-factory.yml", stale:75, level:"privileged", inputs:{}}
]);
const VALID_EVENTS = new Set(["schedule","workflow_dispatch","workflow_run"]);
const BAD = new Set(["failure","cancelled","timed_out","startup_failure","action_required"]);
function headers(token) {
  return {"Accept":"application/vnd.github+json", "User-Agent":"gaslux-liveness-fallback",
    "X-GitHub-Api-Version":"2022-11-28", "Authorization":"Bearer " + token};
}
function validRun(r) {
  return r && Number.isSafeInteger(r.id) && r.id>0 && r.head_branch==="main" &&
    SHA.test(r.head_sha||"") && VALID_EVENTS.has(r.event) &&
    typeof r.status==="string" && typeof r.created_at==="string" &&
    Number.isFinite(Date.parse(r.created_at));
}
async function latest(flow, token, fetcher) {
  const response=await fetcher(API+flow.file+"/runs?branch=main&per_page=20",{
    headers:headers(token),signal:AbortSignal.timeout(12000)});
  if(!response.ok) throw Error("GitHub run listing unavailable for "+flow.file+" HTTP "+response.status);
  const payload=await response.json();
  if(!payload || !Array.isArray(payload.workflow_runs) ||
     !Number.isSafeInteger(payload.total_count))
    throw Error("Malformed run listing for "+flow.file);
  const relevant=payload.workflow_runs.filter(r=>VALID_EVENTS.has(r.event));
  if(relevant.some(r=>!validRun(r))) throw Error("Untrusted run identity for "+flow.file);
  relevant.sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at)||b.id-a.id);
  return relevant[0]||null;
}
async function requestDispatch(flow,token,fetcher) {
  const response=await fetcher(API+flow.file+"/dispatches",{
    method:"POST",headers:{...headers(token),"Content-Type":"application/json"},
    body:JSON.stringify({ref:"main",inputs:flow.inputs}),
    signal:AbortSignal.timeout(12000)});
  if(response.status!==204) throw Error("Dispatch rejected for "+flow.file+" HTTP "+response.status);
}
export async function runScheduler(env,{fetcher=fetch,now=Date.now()}={}) {
  if(env.GASLUX_EXTERNAL_PAUSED!=="false" ||
     env.GASLUX_EXTERNAL_DISPATCH_ENABLED!=="true")
    return {status:"PAUSED",dispatched:[],decisions:[]};
  if(typeof env.GITHUB_ACTIONS_DISPATCH_TOKEN!=="string" ||
     env.GITHUB_ACTIONS_DISPATCH_TOKEN.length<8 || !Number.isFinite(now))
    throw Error("Missing credential or invalid clock; fail closed");
  const dispatched=[],decisions=[], token=env.GITHUB_ACTIONS_DISPATCH_TOKEN;
  for(const flow of WORKFLOWS) {
    if(flow.level==="privileged" && env.GASLUX_EXTERNAL_PRIVILEGED_ENABLED!=="true") {
      decisions.push({workflow:flow.file,status:"PRIVILEGED_DISABLED"}); continue;
    }
    const run=await latest(flow,token,fetcher); // fail closed on GitHub 403/429/500
    if(!run) {decisions.push({workflow:flow.file,status:"NO_ATTESTED_MAIN_RUN"});continue;}
    const age=now-Date.parse(run.created_at);
    if(age<0) throw Error("Future GitHub timestamp; fail closed");
    if(run.status!=="completed") {
      decisions.push({workflow:flow.file,status:"IN_FLIGHT",run_id:run.id});continue;
    }
    if(age<flow.stale*60000) {
      decisions.push({workflow:flow.file,status:"RECENT",run_id:run.id});continue;
    }
    if(flow.level==="privileged" && BAD.has(run.conclusion)) {
      decisions.push({workflow:flow.file,status:"FAILED_HALT",run_id:run.id});continue;
    }
    if(dispatched.length>=2) {
      decisions.push({workflow:flow.file,status:"BUDGET_EXHAUSTED"});continue;
    }
    if(env.GASLUX_EXTERNAL_DRY_RUN!=="false") {
      decisions.push({workflow:flow.file,status:"WOULD_DISPATCH",run_id:run.id});continue;
    }
    await requestDispatch(flow,token,fetcher);
    dispatched.push(flow.file);
    decisions.push({workflow:flow.file,status:"DISPATCHED",run_id:run.id});
  }
  return {status:"OK",dispatched,decisions};
}
export default {
  async scheduled(_controller,env) {
    console.log(JSON.stringify(await runScheduler(env))); // no token or payloads in logs
  },
  async fetch() {return new Response("Not found",{status:404});}
};
