'use strict';
// Bounded phase O UI checks against a dedicated, already-running local server.
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {parseOptions,browserExecutable,redact}=require('./browser_validation.cjs');
async function main(){
 const options=parseOptions(process.argv.slice(2));if(options.help){console.log('Use --url LOOPBACK --out FRESH_DIRECTORY --cuda off [--playwright-module PATH] [--browser-executable PATH]');return;}
 if(options.cuda!=='off')throw new Error('Workspace checks are CPU-only; pass --cuda off.');
 const {chromium}=require(options.playwrightModule||process.env.PLAYWRIGHT_MODULE||'playwright');
 fs.mkdirSync(options.out,{recursive:false});const checks=[],errors=[];let browser,page;
 const save=(name,data)=>fs.writeFileSync(path.join(options.out,name),JSON.stringify(redact(data),null,2)+'\n',{flag:'wx'});
 const check=(name,value)=>{assert(value,name);checks.push(name);console.log('PASS '+name);};
 try{
  browser=await chromium.launch({headless:true,executablePath:browserExecutable(options)});page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));await page.goto(options.url);await page.waitForFunction(()=>document.getElementById('draft-status').textContent.includes('saved')||document.getElementById('preset').options.length>2);
  const get=async url=>(await page.request.get(new URL(url,options.url).href)).json();const info=await get('/api/info'),token=info.control_token;
  const post=async(url,body)=>{const r=await page.request.post(new URL(url,options.url).href,{headers:{'X-Kryptos-Token':token},data:body});return{status:r.status(),body:await r.json()};};
  const wait=async fn=>{const end=Date.now()+30000;while(Date.now()<end){if(await fn())return;await page.waitForTimeout(150);}throw new Error('Timed out waiting for persistence state');};
  check('Dedicated workspace opens without computation',(await get('/api/status')).run===null);
  await page.locator('[data-target="k5"]').click();await page.locator('#ciphertext').fill('EXPLICITK5HYPOTHESIS');await page.locator('#hypothesis-note').fill('Browser-only explicit hypothesis');await page.locator('#advanced-settings').evaluate(d=>d.open=true);await page.locator('#recipe-json').fill('{unfinished draft');
  await wait(async()=> (await get('/api/workspace')).workspace.draft?.fields['recipe-json']==='{unfinished draft');
  await page.reload();await page.waitForFunction(()=>document.getElementById('recipe-json').value==='{unfinished draft');
  check('Incomplete recipes, K5 source and notes survive reload',await page.locator('#ciphertext').inputValue()==='EXPLICITK5HYPOTHESIS'&&await page.locator('#hypothesis-note').inputValue()==='Browser-only explicit hypothesis');
  check('Restoring a draft never starts a job',(await get('/api/status')).run===null);
  await page.locator('#preset').selectOption('demo-optimize');await page.locator('#optimizer-settings').evaluate(d=>d.open=true);
  check('New optimizer strategies default off',!await page.locator('#guided-blocks').isChecked()&&!await page.locator('#elimination-bound').isChecked());
  await page.locator('#guided-blocks').check();await page.locator('#elimination-bound').check();const optional=JSON.parse(await page.locator('#recipe-json').inputValue());
  check('Optional block and mini-bucket controls write bounded request fields',optional.guided_seed.block_size===2&&optional.guided_seed.max_block_completions===676&&optional.elimination_bound==='mini_bucket'&&optional.elimination_max_operations===200000);
  await page.locator('#preset').selectOption('joint-ranked');await page.locator('#joint-pruning').check();check('Joint admissible pruning is explicit',JSON.parse(await page.locator('#recipe-json').inputValue()).pruning==='admissible');
  await page.locator('#preset').selectOption('demo-scan');await page.locator('#backend').selectOption('auto-measured');check('Measured device choice discloses extra work and uses one worker',await page.locator('#workers').inputValue()==='1'&&await page.locator('#workers').isDisabled()&&(await page.locator('#backend-help').textContent()).includes('Extra calibration'));
  await page.locator('#preset').selectOption('joint-ragged');await page.locator('.editing-panel>summary').click();await page.locator('#personal-name').fill('O browser personal control');await page.locator('#save-personal-preset').click();await wait(async()=> (await get('/api/workspace')).workspace.presets.length===1);
  await page.reload();await page.waitForFunction(()=>document.getElementById('personal-presets').options.length===2);await page.locator('.editing-panel>summary').click();await page.locator('#personal-presets').selectOption({label:'O browser personal control'});await page.locator('#load-personal-preset').click();
  check('Personal preset survives reload and loads without execution',(await get('/api/status')).run===null&&await page.locator('#preset-description').textContent()==='Your saved recipe. Review source and bounds before starting.');
  await page.locator('#start-button').click();await wait(async()=> (await get('/api/status')).run?.state==='completed');const original=(await get('/api/status')).run;
  check('Loaded personal preset can explicitly start a bounded control',original.candidates.length>0);
  await page.locator('[data-view="history"]').click();await page.locator('.history-metadata input').nth(0).fill('Small personal control');await page.locator('.history-metadata input').nth(1).fill('control, archived-check');await page.locator('.history-metadata button').last().click();await wait(async()=> (await get('/api/runs')).total===0);
  await page.locator('#history-archive').selectOption('archived');await page.locator('#history-query').fill('Small personal');await page.locator('#history-filters').evaluate(f=>f.requestSubmit());await wait(async()=>await page.locator('.history-card').count()===1);
  check('Tagged archive is searchable and original evidence remains intact',(await get('/api/runs/'+original.id)).run.id===original.id);
  await page.locator('.history-metadata button').last().click();await wait(async()=> (await get('/api/runs')).total===1);
  check('Unarchive reverses visibility without deleting the record',(await get('/api/runs')).runs[0].metadata.tags.includes('control'));
  await page.locator('[data-view="workspace"]').click();const downloadEvent=page.waitForEvent('download');await page.locator('#backup-workspace').click();const downloaded=await downloadEvent;const file=path.join(options.out,'workspace-backup.json');await downloaded.saveAs(file);const bundle=JSON.parse(fs.readFileSync(file,'utf8'));
  check('Workspace backup includes editing state and saved run',bundle.entries.some(e=>e.kind==='editing')&&bundle.entries.some(e=>e.kind==='run'));
  await page.locator('#workspace-backup-file').setInputFiles(file);await page.locator('#verify-workspace-backup').click();await page.waitForFunction(()=>!document.getElementById('restore-workspace').disabled);await page.locator('#restore-workspace').click();await wait(async()=> (await get('/api/workspace/health')).recovered_runs===1);
  const health=await get('/api/workspace/health');const recoveredEditing=(await get('/api/workspace/recovery/'+health.recoveries[0].id)).recovery.editing;check('Recovered draft and presets remain available for explicit loading',recoveredEditing.presets.length===1&&Boolean(recoveredEditing.draft));
  const rows=(await get('/api/runs?archived=all')).runs;const restored=rows.find(r=>r.restored_evidence_only);
  check('Recovery creates a new read-only identity with resume disabled',restored&&restored.id!==original.id&&!restored.can_resume);
  check('Recovery leaves original job and current editing state unchanged',(await get('/api/status')).run.id===original.id&&(await get('/api/workspace')).workspace.presets.length===1);
  const refused=await post('/api/resume',{run_id:restored.id});check('Recovered records cannot be executed through resume',refused.status===404);
  bundle.entries[0].sha256='0'.repeat(64);const bad=path.join(options.out,'tampered-backup.json');fs.writeFileSync(bad,JSON.stringify(bundle));await page.locator('#workspace-backup-file').setInputFiles(bad);await page.locator('#verify-workspace-backup').click();await page.waitForFunction(()=>document.getElementById('workspace-message').classList.contains('error'));check('Tampered backup is rejected before restore',await page.locator('#restore-workspace').isDisabled());
  await page.screenshot({path:path.join(options.out,'desktop-workspace.png'),fullPage:true});
  const before=(await get('/api/workspace')).workspace;await post('/api/workspace',{operation:'draft',revision:before.revision,draft:{schema:'kryptos.editor-draft.v1',note:'other tab'}});await page.locator('[data-view="workbench"]').click();await page.locator('#hypothesis-note').fill('This tab must not overwrite newer state');await wait(async()=> (await page.locator('#draft-status').textContent()).includes('another tab'));
  check('Stale-tab draft conflict is visible and preserves newer state',(await get('/api/workspace')).workspace.draft.note==='other tab');
  await page.setViewportSize({width:390,height:844});for(const view of['workspace','history']){await page.locator('[data-view="'+view+'"]').click();await page.waitForTimeout(150);check(view+' mobile has no horizontal page overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));await page.screenshot({path:path.join(options.out,'mobile-'+view+'.png'),fullPage:true});}
  check('No browser JavaScript errors',errors.length===0);check('No active computation remains',!['running','pausing','stopping'].includes((await get('/api/status')).run?.state));
  save('report.json',{schema:'kryptos.browser-workspace.v1',passed:checks.length,checks,errors,app_version:info.version,script_sha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex'),scope:'Bounded CPU control, durable editing, reversible metadata, inert recovery and mobile rendering; no GPU or solver-efficiency claim.'});console.log(JSON.stringify({passed:checks.length,errors}));
 }catch(e){save('failure.json',{message:e.message,checks,errors});if(page)await page.screenshot({path:path.join(options.out,'failure.png'),fullPage:true});throw e;}finally{if(browser)await browser.close();}
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
