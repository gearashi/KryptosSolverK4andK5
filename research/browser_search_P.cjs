'use strict';
// Finite UI wiring and historical-snapshot checks on a dedicated CPU server.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {parseOptions,browserExecutable,redact}=require('./browser_validation.cjs');
async function main(){
 const options=parseOptions(process.argv.slice(2));
 if(options.help){console.log('Use --url LOOPBACK --out FRESH_DIRECTORY --cuda off');return;}
 if(options.cuda!=='off')throw new Error('Phase P interface controls use bounded CPU jobs.');
 const {chromium}=require(options.playwrightModule||process.env.PLAYWRIGHT_MODULE||'playwright');
 fs.mkdirSync(options.out,{recursive:false});const checks=[],errors=[];let browser,page;
 const save=(name,value)=>fs.writeFileSync(path.join(options.out,name),JSON.stringify(redact(value),null,2)+'\n',{flag:'wx'});
 const check=(name,value)=>{assert(value,name);checks.push(name);console.log('PASS '+name);};
 try{
  browser=await chromium.launch({headless:true,executablePath:browserExecutable(options)});
  page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
  await page.goto(options.url);await page.waitForFunction(()=>document.getElementById('preset').options.length>2);
  const get=async url=>(await page.request.get(new URL(url,options.url).href)).json();
  const wait=async fn=>{const end=Date.now()+40000;while(Date.now()<end){if(await fn())return;await page.waitForTimeout(150);}throw new Error('Timed out waiting for bounded search state');};
  const info=await get('/api/info');check('Opening the dashboard starts no search',(await get('/api/status')).run===null);
  await page.locator('#preset').selectOption('joint-ranked');await page.locator('#joint-strategies').evaluate(d=>d.open=true);
  const ids=['joint-propagation','joint-early-segmentation','joint-branching','joint-shared-key-bound','joint-symmetry'];
  check('All five ranked-joint reductions default off',(await Promise.all(ids.map(id=>page.locator('#'+id).isChecked()))).every(v=>!v));
  for(const id of ids)await page.locator('#'+id).check();
  let request=JSON.parse(await page.locator('#recipe-json').inputValue());
  check('Joint controls write explicit bounded options',request.propagation==='fixed_point'&&request.early_segmentation===true&&request.branching==='constrained'&&request.score_bound==='shared_key'&&request.symmetry==='identical_chunks'&&request.pruning==='admissible'&&request.max_bound_cache_entries===2048);
  await page.locator('#joint-pruning').uncheck();check('Disabling pruning clears the dependent shared-key bound',!await page.locator('#joint-shared-key-bound').isChecked()&&JSON.parse(await page.locator('#recipe-json').inputValue()).score_bound==='independent');
  await page.locator('#joint-shared-key-bound').check();
  await page.locator('[data-target="custom"]').click();await page.locator('#ciphertext').fill('BCDEFG');await page.locator('#cribs').evaluate(e=>e.closest('details').open=true);await page.locator('#cribs').fill('');
  await page.locator('#advanced-settings').evaluate(d=>d.open=true);
  request={target:'custom',ciphertext:'BCDEFG',cribs:[],alphabet:'standard',width:2,period:1,order:'ST',top:5,
   model_path:'research/models/multilingual-001/artifacts/pg1342-english-trigram.json',pruning:'admissible',propagation:'fixed_point',early_segmentation:true,branching:'constrained',score_bound:'shared_key',symmetry:'identical_chunks',max_bound_cache_entries:2048,max_evaluations:1,max_states:100000,time_limit_seconds:2};
  await page.locator('#recipe-json').fill(JSON.stringify(request));await page.locator('#recipe-json').blur();
  await page.locator('#start-button').click();await wait(async()=>['limited','failed'].includes((await get('/api/status')).run?.state));
  const first=(await get('/api/status')).run;check('A bounded joint run saves an exact resumable frontier',first.state==='limited'&&first.can_resume&&first.exact_checkpoint&&first.result.evaluated===1);
  check('Interleaved order counts disclose completion blocks',first.result.column_orders_visited===null&&Number.isInteger(first.result.route_completion_blocks));
  await wait(async()=>!await page.locator('#pause-button').isDisabled()&&(await page.locator('#pause-button').textContent()).includes('Resume'));
  await page.locator('#pause-button').click();await wait(async()=>{const r=(await get('/api/status')).run;return r?.state==='limited'&&r.result.evaluated>first.result.evaluated;});
  const resumed=(await get('/api/status')).run;check('Resume preserves options and advances one bounded candidate',resumed.id===first.id&&resumed.result.evaluated===2&&resumed.request.score_bound==='shared_key');
  await wait(async()=>(await page.locator('#candidate-list').textContent()).includes('Propagate column'));
  check('Candidate evidence names the saved search techniques',(await page.locator('#candidate-list').textContent()).includes('Respect shared keys'));
  await page.locator('#preset').selectOption('demo-optimize');await page.locator('#optimizer-settings').evaluate(d=>d.open=true);
  check('Residual reuse and cheap bounds default off',!await page.locator('#residual-cache').isChecked()&&!await page.locator('#cheap-bound-first').isChecked());
  await page.locator('#residual-cache').check();await page.locator('#cheap-bound-first').check();request=JSON.parse(await page.locator('#recipe-json').inputValue());
  check('Optimizer controls retain explicit work caps',request.residual_cache==='components'&&request.residual_cache_max_entries===256&&request.residual_cache_max_assignments===256&&request.residual_cache_max_operations===200000&&request.cheap_bound_first===true);
  await page.locator('#start-button').click();await wait(async()=>{const r=(await get('/api/status')).run;return r?.id!==first.id&&['completed','failed','limited'].includes(r?.state);});
  const optimized=(await get('/api/status')).run;check('Optional optimizer controls execute a bounded exact job',optimized.state==='completed'&&optimized.result.optimization.search.complete);
  await page.locator('[data-view="campaigns"]').click();check('Shared incomplete scans default off',await page.locator('#campaign-share').inputValue()==='off');
  const base={kind:'accelerated',command:'optimize-plus',backend:'cpu',workers:1,batch_size:10,max_batches:1,time_limit_seconds:10,ranking_mode:'certified',adaptive:false,
   request:{target:'custom',ciphertext:'BCDEFG',cribs:[],alphabet:'standard',layer_model:'scheduled',stages:[{operation:'substitution',key_id:'k',key_length:1,cipher:'vigenere',offset:0}],model_path:'research/models/multilingual-001/artifacts/pg1342-english-trigram.json'}};
  await page.locator('#campaign-base').evaluate(e=>e.closest('details').open=true);await page.locator('#campaign-base').fill(JSON.stringify(base));
  await page.locator('#campaign-axes').fill(JSON.stringify([{path:'request.stages.0.offset',values:[0,1,2]}]));await page.locator('#campaign-share').selectOption('compatible');
  await wait(async()=>(await get('/api/workspace')).workspace.draft?.fields['campaign-share']==='compatible');
  await page.reload();await page.waitForFunction(()=>document.getElementById('campaign-share').value==='compatible');
  check('Sharing preference survives reload without launching a campaign',(await get('/api/status')).campaign===null);
  await page.locator('[data-view="campaigns"]').click();await page.locator('#preview-campaign').click();await page.waitForFunction(()=>!document.getElementById('start-campaign').disabled);
  check('Campaign preview creates no computation',(await get('/api/status')).campaign===null);
  await page.locator('#start-campaign').click();await wait(async()=>['completed','failed'].includes((await get('/api/status')).campaign?.state));
  const campaign=(await get('/api/status')).campaign;check('Three jobs continue one certified family',campaign.state==='completed'&&campaign.jobs.length===3&&new Set(campaign.jobs.map(j=>j.run_id||j.alias_run_id)).size===1);
  const snapshots=campaign.jobs.map(j=>j.scan_snapshot);
  check('Committed work covers disjoint pages and exactly26 candidates',snapshots.map(s=>s.completed_offset_decimal).join(',')==='10,20,26'&&snapshots.reduce((n,s)=>n+Number(s.work.new_candidate_evaluations_decimal),0)===26);
  check('Earlier job snapshots stay partial after owner completion',snapshots[0].top_k_exact===false&&snapshots[0].candidates.length===10&&snapshots[2].top_k_exact===true);
  await wait(async()=>(await page.locator('#campaign-progress').textContent()).includes('3 / 3 jobs finished'));const campaignHeadline=await page.locator('#campaign-progress').textContent();
  check('Campaign headline counts completed-family aliases separately from shared prefixes',campaign.progress.deduplicated===0&&campaignHeadline.includes('0 completed-family aliases')&&!campaignHeadline.includes('equivalent families reused'));
  await wait(async()=>await page.locator('#campaign-jobs tbody tr').count()===3);await page.locator('#campaign-jobs tbody tr').first().getByRole('button',{name:'Inspect',exact:true}).click();
  await page.locator('#run-dialog').waitFor({state:'visible'});const inspected=JSON.parse(await page.locator('#run-json').textContent());
  check('Inspecting the first job uses its historical partial result',inspected.state==='incomplete'&&inspected.result.complete===false&&inspected.result.top_k_exact===false&&inspected.shared_scan_snapshot.completed_offset_decimal==='10'&&inspected.candidates.length===10);
  save('inspected-historical-snapshot.json',inspected);await page.screenshot({path:path.join(options.out,'desktop-historical-snapshot.png'),fullPage:true});await page.locator('#close-dialog').click();
  await page.screenshot({path:path.join(options.out,'desktop-search.png'),fullPage:true});await page.setViewportSize({width:390,height:844});
  for(const view of ['workbench','campaigns']){await page.locator('[data-view="'+view+'"]').click();await page.waitForTimeout(150);check(view+' mobile has no horizontal overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));}
  await page.screenshot({path:path.join(options.out,'mobile-campaign.png'),fullPage:true});
  check('No browser JavaScript errors',errors.length===0);check('No active computation remains',!['running','pausing','stopping'].includes((await get('/api/status')).run?.state));
  save('report.json',{schema:'kryptos.browser-search-P.v1',passed:checks.length,checks,errors,app_version:info.version,script_sha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),scope:'Default-off options, exact frontier continuation, saved-technique labels and immutable shared-scan snapshots; bounded CPU controls only.'});
 }catch(e){save('failure.json',{message:e.message,checks,errors});if(page)await page.screenshot({path:path.join(options.out,'failure.png'),fullPage:true});throw e;}finally{if(browser)await browser.close();}
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
