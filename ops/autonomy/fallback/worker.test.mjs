import {test} from "node:test";
import assert from "node:assert/strict";
import {runScheduler} from "./worker.mjs";

const NOW=Date.parse("2026-11-23T07:00:00Z"), SHA="a".repeat(40);
const base={GASLUX_EXTERNAL_PAUSED:"false",GASLUX_EXTERNAL_DISPATCH_ENABLED:"true",
  GASLUX_EXTERNAL_PRIVILEGED_ENABLED:"false",GASLUX_EXTERNAL_DRY_RUN:"false",
  GITHUB_ACTIONS_DISPATCH_TOKEN:"offline-test-credential"};
function item(age=60,overrides={}) {
  return {id:123,head_sha:SHA,head_branch:"main",event:"schedule",
    status:"completed",conclusion:"success",
    created_at:new Date(NOW-age*60000).toISOString(),...overrides};
}
function fixture(rows=[],http=200) {
  const calls=[];
  const fetcher=async (url,args)=>{
    calls.push({url,method:args.method||"GET",body:args.body});
    if(args.method==="POST") return {status:204};
    return {status:http,ok:http===200,
      json:async()=>({total_count:rows.length,workflow_runs:rows})};
  };
  return {calls,fetcher};
}
test("paused by default, no API calls",async()=>{
  const f=fixture([item()]);
  const result=await runScheduler({...base,GASLUX_EXTERNAL_PAUSED:undefined},{fetcher:f.fetcher,now:NOW});
  assert.equal(result.status,"PAUSED");assert.equal(f.calls.length,0);
});
test("absence of opt-in dispatch refuses writes",async()=>{
  const f=fixture([item()]);
  const out=await runScheduler({...base,GASLUX_EXTERNAL_DISPATCH_ENABLED:undefined},{fetcher:f.fetcher,now:NOW});
  assert.equal(out.status,"PAUSED");assert.equal(f.calls.length,0);
});
test("recent run does not duplicate",async()=>{
  const f=fixture([item(5)]);
  const result=await runScheduler(base,{fetcher:f.fetcher,now:NOW});
  assert.deepEqual(result.dispatched,[]);
  assert.equal(result.decisions[0].status,"RECENT");
  assert.equal(f.calls.length,1);
});
test("stale lifecycle is only default permitted dispatch",async()=>{
  const f=fixture([item(120)]);
  const result=await runScheduler(base,{fetcher:f.fetcher,now:NOW});
  assert.deepEqual(result.dispatched,["gaslux-agent-lifecycle-research.yml"]);
  const post=f.calls.filter(x=>x.method==="POST");
  assert.equal(post.length,1);
  assert.deepEqual(JSON.parse(post[0].body),{ref:"main",inputs:{mint_live_boot:"false"}});
  assert.equal(result.decisions.filter(x=>x.status==="PRIVILEGED_DISABLED").length,3);
});
test("in-flight run never duplicates",async()=>{
  const f=fixture([item(150,{status:"queued"})]);
  const result=await runScheduler(base,{fetcher:f.fetcher,now:NOW});
  assert.deepEqual(result.dispatched,[]);
  assert.equal(result.decisions[0].status,"IN_FLIGHT");
});
test("dry-run never POSTs",async()=>{
  const f=fixture([item(150)]);
  const result=await runScheduler({...base,GASLUX_EXTERNAL_DRY_RUN:"true"},{fetcher:f.fetcher,now:NOW});
  assert.equal(result.decisions[0].status,"WOULD_DISPATCH");
  assert.equal(f.calls.filter(x=>x.method==="POST").length,0);
});
test("malformed identity refused before any POST",async()=>{
  for(const row of [item(120,{head_sha:"invalid"}),item(120,{head_branch:"dev"})]){
    const f=fixture([row]);
    await assert.rejects(runScheduler(base,{fetcher:f.fetcher,now:NOW}),/Untrusted run identity/);
    assert.equal(f.calls.filter(x=>x.method==="POST").length,0);
  }
});
test("GitHub API failure blocks dispatch",async()=>{
  const f=fixture([item(120)],503);
  await assert.rejects(runScheduler(base,{fetcher:f.fetcher,now:NOW}),/listing unavailable/);
  assert.equal(f.calls.filter(x=>x.method==="POST").length,0);
});
test("missing run is not dispatch authorization",async()=>{
  const f=fixture([]);
  const result=await runScheduler(base,{fetcher:f.fetcher,now:NOW});
  assert.deepEqual(result.dispatched,[]);
  assert.equal(result.decisions[0].status,"NO_ATTESTED_MAIN_RUN");
});
test("failed generated code not retried by fallback",async()=>{
  const f=fixture([item(150,{conclusion:"failure"})]);
  const result=await runScheduler({...base,GASLUX_EXTERNAL_PRIVILEGED_ENABLED:"true"},{fetcher:f.fetcher,now:NOW});
  assert.equal(result.decisions.filter(x=>x.status==="FAILED_HALT").length,3);
  assert.deepEqual(result.dispatched,["gaslux-agent-lifecycle-research.yml"]);
});
test("token missing fails closed",async()=>{
  await assert.rejects(runScheduler({...base,GITHUB_ACTIONS_DISPATCH_TOKEN:undefined},{now:NOW}),/credential/);
});
test("no public HTTP dispatch endpoint",async()=>{
  const {default:worker}=await import("./worker.mjs");
  assert.equal((await worker.fetch(new Request("https://example.invalid"))).status,404);
});
