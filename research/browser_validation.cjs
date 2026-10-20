// Portable local-dashboard validation. The server must already be running.
// Every output folder is new; this runner never modifies historical evidence.
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

function parseOptions(argv) {
  const options = {url: 'http://127.0.0.1:8768/', cuda: 'auto', suite: 'all', timeoutMs: 90000};
  const fields = {'--url':'url', '--out':'out', '--playwright-module':'playwrightModule',
    '--browser-executable':'browserExecutable', '--cuda':'cuda', '--suite':'suite', '--timeout-ms':'timeoutMs'};
  for (let i = 0; i < argv.length; i++) {
    const option = argv[i];
    if (option === '--help' || option === '-h') return {help: true};
    if (!fields[option] || i + 1 === argv.length || argv[i + 1].startsWith('--')) {
      throw new Error(`Unknown option or missing value: ${option}. Use --help.`);
    }
    options[fields[option]] = argv[++i];
  }
  const url = new URL(options.url);
  if (!['http:', 'https:'].includes(url.protocol) || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('Use a loopback HTTP(S) origin with no credentials, query, or path.');
  }
  if (url.port === '8767') throw new Error('Port8767 is reserved for the user app; use a separate validation server.');
  options.url = url.href;
  if (!options.out) throw new Error('--out must name a fresh evidence directory.');
  options.out = path.resolve(options.out);
  if (!['off', 'auto', 'required'].includes(options.cuda)) throw new Error('--cuda must be off, auto, or required.');
  if (!['n', 'devices', 'all'].includes(options.suite)) throw new Error('--suite must be n, devices, or all.');
  if (options.suite === 'n' && options.cuda === 'required') throw new Error('Use the devices or all suite to require a CUDA comparison.');
  options.timeoutMs = Number(options.timeoutMs);
  if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 5000 || options.timeoutMs > 300000) {
    throw new Error('--timeout-ms must be an integer5000..300000.');
  }
  return options;
}

function loadPlaywright(options, env = process.env) {
  const requested = options.playwrightModule || env.PLAYWRIGHT_MODULE;
  const paths = requested ? [requested] : ['playwright', 'playwright-core',
    path.resolve(path.dirname(process.execPath), '..', 'node_modules', 'playwright'),
    path.join(os.homedir(), '.cache', 'codex-runtimes', 'codex-primary-runtime', 'dependencies', 'node', 'node_modules', 'playwright')];
  for (const candidate of paths) {
    try {
      const module = require(candidate);
      if (!module.chromium) throw new Error('Module has no Chromium browser API.');
      return module;
    } catch (error) {
      if (requested) throw new Error(`Could not load the explicitly supplied Playwright module: ${error.message}`);
    }
  }
  throw new Error('Playwright is unavailable. Install playwright or pass --playwright-module / set PLAYWRIGHT_MODULE. No dependencies were downloaded.');
}

function browserExecutable(options, env = process.env) {
  const explicit = options.browserExecutable || env.CHROME_PATH || env.CHROMIUM_PATH;
  if (explicit) {
    const resolved = path.resolve(explicit);
    if (!fs.existsSync(resolved)) throw new Error('The supplied browser executable does not exist.');
    return resolved;
  }
  const candidates = process.platform === 'win32' ? [
    env.PROGRAMFILES && path.join(env.PROGRAMFILES, 'Google', 'Chrome', 'Application', 'chrome.exe'),
    env['PROGRAMFILES(X86)'] && path.join(env['PROGRAMFILES(X86)'], 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
    env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'Google', 'Chrome', 'Application', 'chrome.exe')
  ] : process.platform === 'darwin' ? ['/Applications/Google Chrome.app/Contents/MacOS/Google Chrome']
    : ['/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/google-chrome'];
  return candidates.find(candidate => candidate && fs.existsSync(candidate));
}

function redact(value) {
  if (Array.isArray(value)) return value.map(redact);
  if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, child]) =>
    [key, /^(control_token|authorization|cookie|set-cookie)$/i.test(key) ? '[REDACTED]' : redact(child)]));
  return value;
}

function assertNoManagedControls(value) {
  if (Array.isArray(value)) return value.forEach(assertNoManagedControls);
  if (value && typeof value === 'object') for (const [key, child] of Object.entries(value)) {
    assert(!['checkpoint_path', 'resume_path', 'checkpoint_written'].includes(key), `Export contains executable managed control: ${key}`);
    assertNoManagedControls(child);
  }
}

const sha256 = value => crypto.createHash('sha256').update(value).digest('hex');

async function run(options) {
 const {chromium} = loadPlaywright(options);
 const executablePath = browserExecutable(options);
 if (fs.existsSync(options.out)) throw new Error('Evidence directory already exists; choose a fresh --out path.');
 fs.mkdirSync(options.out, {recursive:true});
 const out = options.out;
 let browser, page, token;
 const checks=[], errors=[], runIds=[], requests=[], skips=[], createdRuns=new Set(), createdCampaigns=new Set();
 const startedAt = new Date().toISOString();
 const evidence = {schema:'kryptos.browser-validation.v2',started_at:startedAt,origin:options.url,
   suite:options.suite,cuda_policy:options.cuda,node_version:process.version,script_sha256:sha256(fs.readFileSync(__filename))};
 const save = (name,value) => fs.writeFileSync(path.join(out,name),JSON.stringify(redact(value),null,2)+'\n',{flag:'wx'});
 const check = (name,value) => {assert(value,name);checks.push(name);console.log('PASS '+name);};
 const get = async url => {
   const response = await page.request.get(new URL(url,options.url).href);
   if (!response.ok()) throw new Error(`${url}: HTTP${response.status()}`);
   return response.json();
 };
 const until = async(test,label,limit=options.timeoutMs) => {
   const end=Date.now()+limit;
   while(Date.now()<end){const s=await get('/api/status');if(test(s))return s;
     if(s.run?.state==='failed'||s.campaign?.state==='failed')throw new Error(`${label}: ${s.run?.error||s.campaign?.error||'failed'}`);
     await page.waitForTimeout(200);}
   throw new Error('Timeout: '+label);
 };
 const response = suffix => page.waitForResponse(r=>new URL(r.url()).pathname===suffix&&r.request().method()==='POST').then(async r=>{
   const body=await r.json();if(!r.ok())throw new Error(body.error||`${suffix}: HTTP${r.status()}`);
   if(suffix==='/api/start'&&body.run)createdRuns.add(body.run.id);
   if(suffix==='/api/campaigns/start'&&body.campaign)createdCampaigns.add(body.campaign.id);
   return body;
 });
 const shot = async name => {await page.evaluate(()=>{document.activeElement?.blur();document.querySelectorAll('textarea').forEach(e=>{e.scrollTop=0;e.scrollLeft=0;});window.scrollTo({top:0,behavior:'instant'});});await page.screenshot({path:path.join(out,name+'.png'),fullPage:true});};
 const remember = async(run,name) => {runIds.push(run.id);const exported=await get('/api/export?run_id='+run.id);assertNoManagedControls(exported);save(name+'.json',exported);};
 const openDetails = async id => {if(!await page.locator('#'+id).evaluate(e=>e.open))await page.locator('#'+id+'>summary').click();};
 const begin = async() => {const pending=response('/api/start');await page.locator('#start-button').click();const r=await pending;assert(r.run,r.error);return r.run;};
 const finished = async(run,label) => (await until(s=>s.run?.id===run.id&&!['running','pausing','stopping'].includes(s.run.state),label)).run;
 const cleanup = async() => {
   if(!page||!token)return {stopped:[]};
   const result={stopped:[]};
   try{const status=await get('/api/status');let endpoint,body;
     if(createdCampaigns.has(status.campaign?.id)&&['running','pausing','stopping'].includes(status.campaign.state)){
       endpoint='/api/campaigns/stop';body={campaign_id:status.campaign.id};
     }else if(createdRuns.has(status.run?.id)&&['running','pausing','stopping'].includes(status.run.state)){
       endpoint='/api/stop';body={run_id:status.run.id};
     }
     if(endpoint){const response=await page.request.post(new URL(endpoint,options.url).href,{data:body,headers:{'X-Kryptos-Token':token}});result.stopped.push({endpoint,...body,status:response.status()});}
   }catch(error){result.error=error.message;}
   return result;
 };
 try {
  browser=await chromium.launch({headless:true,...(executablePath?{executablePath}:{})});
  evidence.browser_version=browser.version();
  page=await browser.newPage({viewport:{width:1440,height:1080},acceptDownloads:true});
  page.setDefaultTimeout(options.timeoutMs);await page.emulateMedia({reducedMotion:'reduce'});
  page.on('pageerror',error=>errors.push(error.message));
  page.on('request',request=>{if(request.method()==='POST')requests.push({path:new URL(request.url()).pathname,body:redact(request.postDataJSON())});});
  await page.goto(options.url);await page.waitForFunction(()=>!document.getElementById('start-button').disabled);
  const initial=await get('/api/status');
  check('Dedicated server opens idle without an automatic search',initial.run===null&&!initial.campaign);
  const info=await get('/api/info');token=info.control_token;
  evidence.app_version=info.version;evidence.capabilities=redact(info.capabilities);
  evidence.served_static_sha256={};for(const name of ['index.html','app.js','style.css']){
    const r=await page.request.get(new URL(name==='index.html'?'/':'/static/'+name,options.url).href);assert(r.ok());evidence.served_static_sha256[name]=sha256(await r.body());
  }
  check('Server provides ranked preset and all validation protocols',info.presets.some(p=>p.id==='joint-ranked')&&['validate-holdout','validate-controls','validate-k4-shaped','validate-ablations'].every(id=>info.validation_presets.some(p=>p.id===id)));
  if(options.suite!=='devices') {

  await page.locator('#preset').selectOption('joint-ranked');check('Ranked route and completion bounds are editable',await page.locator('#field-max_orders').count()===1&&await page.locator('#field-max_evaluations').count()===1);
  let run=await finished(await begin(),'ranked joint');check('Ranked joint exhausts its declared small family',run.state==='completed'&&run.result.top_k_exact&&run.result.complete&&run.candidates.length>0);await remember(run,'ranked-joint');
  await page.waitForFunction(()=>document.getElementById('result-summary').textContent.includes('exact over declared family'));await page.locator('.candidate>summary').first().click();await shot('desktop-ranked-joint');
  await page.locator('.candidate').first().getByRole('button',{name:'Replay + trace letters'}).click();await page.waitForFunction(()=>!document.getElementById('inspection-panel').hidden);check('Ranked joint candidate independently replays through importer',await page.locator('#inspection-title').textContent()==='Recipe and clues agree.');save('ranked-inspection.json',JSON.parse(await page.locator('#inspection-json').textContent()));await page.locator('#trace-source .trace-cell').nth(3).click();await shot('desktop-ranked-trace');
  await page.locator('[data-view="workbench"]').click();await page.locator('#preset').selectOption('demo-optimize');await openDetails('optimizer-settings');check('Guided and decomposition controls reflect preset',await page.locator('#guided-enabled').isChecked()&&await page.locator('#decomposition-enabled').isChecked());
  await page.locator('#guided-seed').fill('17');await page.locator('#guided-seed').dispatchEvent('change');await page.locator('#guided-evaluations').fill('128');await page.locator('#guided-evaluations').dispatchEvent('change');await page.locator('#groups-enabled').check();let recipe=JSON.parse(await page.locator('#recipe-json').inputValue());check('Editing guided controls preserves custom remaining bounds',recipe.guided_seed.restarts===4&&recipe.guided_seed.max_sweeps===4&&recipe.guided_seed.seed===17&&recipe.guided_seed.max_evaluations===128&&recipe.decomposition==='auto');
  run=await finished(await begin(),'guided exact control');check('Guided decomposition control finishes with replayed candidate',run.state==='completed'&&run.candidates.length>0&&run.request.guided_seed.seed===17);await remember(run,'guided-decomposition');await page.waitForFunction(()=>document.getElementById('result-summary').textContent.includes('Maximum score: proven'));await page.locator('.candidate>summary').first().click();check('Exact candidate displays its matching score and frozen model provenance',await page.locator('.candidate').first().textContent().then(t=>t.includes('Displayed model score')&&t.includes('Frozen model file SHA-256')));await shot('desktop-guided-decomposition');
  // A large synthetic family, bounded at each two-second/256-node slice.
  await page.locator('#preset').selectOption('demo-optimize');recipe=JSON.parse(await page.locator('#recipe-json').inputValue());Object.assign(recipe,{stages:[{operation:'substitution',period:8}],max_nodes:100000,max_frontier:10000,decomposition:'off'});delete recipe.guided_seed;await openDetails('advanced-settings');await page.locator('#recipe-json').fill(JSON.stringify(recipe));run=await begin();
  let state=await until(s=>s.run?.id===run.id&&s.run.exact_checkpoint&&s.run.state==='running','first exact frontier');await page.waitForFunction(()=>!document.getElementById('pause-button').disabled);await page.locator('#pause-button').click();state=await until(s=>s.run?.id===run.id&&s.run.state==='paused','exact pause');const oldNodes=state.run.progress.completed,oldSequence=state.run.exact_checkpoint.sequence,oldFrontier=state.run.progress.frontier_progress_nodes;assert(Number.isSafeInteger(oldFrontier));check('Exact pause saves a checked frontier and node count',oldNodes>0&&oldSequence>0&&state.run.can_resume);
  await page.waitForFunction(()=>document.getElementById('pause-button').textContent==='Resume exact search');await shot('desktop-exact-paused');await page.locator('#pause-button').click();state=await until(s=>s.run?.id===run.id&&s.run.progress.frontier_progress_nodes>oldFrontier,'exact frontier continuation');check('Exact resume advances the frontier, not only reprocessed-node work',state.run.exact_checkpoint.sequence>oldSequence&&state.run.progress.completed>oldNodes&&state.run.progress.frontier_progress_nodes>oldFrontier);await page.locator('#stop-button').click();state=await until(s=>s.run?.id===run.id&&s.run.state==='stopped','exact stop');check('Stop preserves committed exact progress',state.run.progress.completed>=oldNodes&&state.run.exact_checkpoint);await remember(state.run,'exact-frontier');
  // A finite grammar yields three literal families; second campaign reuses them.
  await page.locator('#preset').selectOption('demo-scan');await page.locator('[data-view="campaigns"]').click();await page.locator('#campaign-use-workbench').click();await page.locator('#campaign-mode').selectOption('generator');
  let base=JSON.parse(await page.locator('#campaign-base').inputValue());Object.assign(base,{backend:'cpu',workers:1,batch_size:26,max_batches:10,time_limit_seconds:60,ranking_mode:'certified'});await page.getByText('Frozen base configuration',{exact:true}).click();await page.locator('#campaign-base').fill(JSON.stringify(base));await page.locator('#campaign-generator').fill(JSON.stringify({patterns:['S','ST','TS'],periods:[2],alphabets:['standard'],ciphers:['vigenere'],routes:['identity','reverse'],max_expansions:32}));await page.locator('#campaign-name').fill('Browser N declared grammar');let pending=response('/api/campaigns/preview');await page.locator('#preview-campaign').click();let preview=await pending;assert(preview.preview,preview.error);check('Generator preview records expansion and literal deduplication',preview.preview.generation.expanded_recipes===5&&preview.preview.job_count===3&&preview.preview.generation.literal_duplicates_removed===2);check('Generator preview sends no axes and launches no run',requests.at(-1).body.generator&&!Object.hasOwn(requests.at(-1).body,'axes')&&(await get('/api/status')).run.id===run.id);await shot('desktop-generator-preview');
  await page.waitForFunction(()=>!document.getElementById('start-campaign').disabled);pending=response('/api/campaigns/start');await page.locator('#start-campaign').click();let campaign=(await pending).campaign;assert(campaign);await page.waitForFunction(()=>!document.getElementById('campaign-pause').disabled);await page.locator('#campaign-pause').click();state=await until(s=>s.campaign?.id===campaign.id&&s.campaign.state==='paused','generated campaign pause');check('Campaign pauses its declared queue',state.campaign.state==='paused');await page.waitForFunction(()=>document.getElementById('campaign-pause').textContent==='Resume campaign');await page.locator('#campaign-pause').click();state=await until(s=>s.campaign?.id===campaign.id&&s.campaign.state==='completed','generated campaign');campaign=state.campaign;save('generated-campaign.json',campaign);check('Generated campaign completes all three declared jobs',campaign.progress.finished===3&&campaign.jobs.every(j=>['completed','equivalent'].includes(j.state)));
  await page.locator('#campaign-name').fill('Browser N reuse the committed grammar');await page.locator('#preview-campaign').click();await page.waitForFunction(()=>!document.getElementById('start-campaign').disabled);pending=response('/api/campaigns/start');await page.locator('#start-campaign').click();const next=(await pending).campaign;state=await until(s=>s.campaign?.id===next.id&&s.campaign.state==='completed','cross campaign reuse');save('reused-campaign.json',state.campaign);check('Second campaign reuses completed families with provenance',state.campaign.jobs.every(j=>j.state==='equivalent'&&j.alias_campaign_id===campaign.id&&j.alias_run_id&&j.candidates.length));await page.waitForFunction(()=>document.getElementById('campaign-jobs').textContent.includes('Candidates carry this job'));await shot('desktop-cross-campaign-reuse');
  await page.locator('#campaign-jobs').getByRole('button',{name:'Replay first'}).nth(1).click();await page.waitForFunction(()=>!document.getElementById('inspection-panel').hidden);check('Cross-campaign alias replays its own transported recipe',await page.locator('#inspection-title').textContent()==='Recipe and clues agree.');save('cross-campaign-inspection.json',JSON.parse(await page.locator('#inspection-json').textContent()));
  // Only a tiny authored UI control; the reserved K4-shaped bank is not rerun.
  await page.locator('[data-view="validation"]').click();await page.locator('#validation-preset').selectOption('validate-k4-shaped');check('Reserved K4-shaped preset preserves its30-second declared budget',JSON.parse(await page.locator('#validation-json').inputValue()).time_limit_seconds===30);
  await page.locator('#validation-preset').selectOption('validate-ablations');check('Ablation protocol exposes withheld positions',await page.locator('#validation-holdout-fields').isVisible());const model=JSON.parse(await page.locator('#validation-json').inputValue()).model_paths[0];const protocol={target:'custom',ciphertext:'BDECFGHI',cribs:[{start:1,text:'AB'},{start:7,text:'GH'}],withheld_positions:[1],model_paths:[model],model_bank:[{id:'browser-authored-cycle',layer_model:'general',alphabet:'standard',stages:[{operation:'substitution',period:1},{operation:'gather',permutation:[0,2,3,1,4,5,6,7]}]}],schedule_semantics:'recompute',max_candidates_per_family:26,max_total_candidates:100,time_limit_seconds:10,top:3};await page.locator('#validation-json').fill(JSON.stringify(protocol));pending=response('/api/start');await page.locator('#start-validation').click();let start=await pending;assert(start.run,start.error);run=await finished(start.run,'authored ablation');check('Authored ablation completes baseline and two refits',run.state==='completed'&&run.result.complete&&run.result.records.length===3);await remember(run,'authored-ablations');await page.waitForFunction(()=>document.querySelectorAll('#validation-result tbody tr').length===3);check('Ablation table displays completed family comparisons',await page.locator('#validation-result').textContent().then(t=>t.includes('Baseline')&&t.includes('Remove stage 2')&&t.includes('censored comparisons')));check('Complete contradictory ablation has no fabricated winner',await page.locator('#validation-result tbody tr').nth(1).textContent().then(t=>t.includes('no fitting plaintext')&&t.includes('no prediction')&&t.includes('unavailable')));check('Ablation row labels retain readable width',await page.locator('#validation-result tbody td').first().evaluate(e=>e.getBoundingClientRect().width>=115));await shot('desktop-ablations');
  await page.setViewportSize({width:390,height:844});for(const view of ['validation','campaigns','workbench','inspector']){await page.locator(`[data-view="${view}"]`).click();check(view+' mobile has no horizontal page overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));await shot('mobile-'+view);}
  await page.locator('[data-view="history"]').click();await page.waitForFunction(()=>document.querySelectorAll("#history-list .history-card").length>0);check("Saved managed search offers frontier resume",await page.locator("#history-list").getByRole("button",{name:"Resume exact search",exact:true}).count()>0);
  }
  if(options.suite!=='n') {
    await page.setViewportSize({width:1440,height:1080});
    await page.locator('[data-view="workbench"]').click();
    // Enough finite CPU pages to exercise boundary updates, without scanning
    // the family to exhaustion. All controls below operate through the UI.
    await page.locator('#preset').selectOption('demo-scan');
    const resourceRequest=JSON.parse(await page.locator('#recipe-json').inputValue());resourceRequest.stages[0].period=4;
    await openDetails('advanced-settings');await page.locator('#recipe-json').fill(JSON.stringify(resourceRequest,null,2));
    await page.locator('#backend').selectOption('cpu');await page.locator('#workers').selectOption('1');
    for(const [id,value]of[['field-setting-batch_size','8'],['field-setting-max_batches','1000']]){
      await page.locator('#'+id).fill(value);await page.locator('#'+id).dispatchEvent('change');
    }
    const resourceRun=await begin();await page.waitForFunction(()=>!document.getElementById('resource-controls').hidden);
    await openDetails('resource-controls');await page.locator('#resource-workers').selectOption('2');
    await page.locator('#resource-idle').fill('100');await page.locator('#resource-target').fill('0.2');await page.locator('#apply-resources').click();
    let resourceState=await until(s=>s.run?.id===resourceRun.id&&s.run.settings.workers===2&&s.run.resource_events?.length>0,'resource boundary update');
    check('Resource controls apply at a committed boundary',resourceState.run.settings.idle_ms===100);
    await page.waitForFunction(()=>!document.getElementById('pause-button').disabled);await page.locator('#pause-button').click();
    resourceState=await until(s=>s.run?.id===resourceRun.id&&s.run.state==='paused','CPU scan pause');
    const oldOffset=Number(resourceState.run.progress.completed_decimal??resourceState.run.progress.completed);
    check('CPU scan pause saves committed page progress',oldOffset>0&&resourceState.run.can_resume);
    await page.waitForFunction(()=>document.getElementById('pause-button').textContent==='Resume scan');await page.locator('#pause-button').click();
    resourceState=await until(s=>s.run?.id===resourceRun.id&&Number(s.run.progress.completed_decimal??s.run.progress.completed)>oldOffset,'CPU scan continuation');
    await page.locator('#resource-adaptive').check();await page.locator('#apply-resources').click();
    await until(s=>s.run?.id===resourceRun.id&&s.run.settings.adaptive===true,'adaptive resource boundary');
    await page.locator('#stop-button').click();resourceState=await until(s=>s.run?.id===resourceRun.id&&s.run.state==='stopped','CPU resource scan stop');
    check('CPU scan resume advances pages and adaptive settings are recorded',Number(resourceState.run.progress.completed_decimal??resourceState.run.progress.completed)>oldOffset&&resourceState.run.settings.adaptive===true);
    await remember(resourceState.run,'cpu-resource-controls');await shot('desktop-resource-controls');
    const runPage=async backend=>{
      await page.locator('#preset').selectOption('demo-scan');
      const request=JSON.parse(await page.locator('#recipe-json').inputValue());request.stages[0].period=3;
      await openDetails('advanced-settings');await page.locator('#recipe-json').fill(JSON.stringify(request,null,2));
      await page.locator('#backend').selectOption(backend);await page.locator('#ranking-mode').selectOption('certified');
      if(backend==='cpu')await page.locator('#workers').selectOption('1');
      for(const [id,value]of[['field-setting-batch_size','128'],['field-setting-max_batches','1']]){
        await page.locator('#'+id).fill(value);await page.locator('#'+id).dispatchEvent('change');
      }
      const run=await finished(await begin(),backend+' certified page');
      check(backend+' commits exactly one128-candidate page',Number(run.progress.completed_decimal??run.progress.completed)===128&&run.backends_used.includes(backend));
      check(backend+' retains a certified ranking',run.ranking_exact_over_committed_pages===true&&run.candidates.length>0);
      await remember(run,backend+'-certified');
      await page.waitForFunction(id=>document.getElementById('run-id').textContent.includes(id),run.id.slice(0,12));
      await page.locator('.candidate>summary').first().click();await shot('desktop-'+backend+'-candidate');
      return run;
    };
    const cpu=await runPage('cpu');let exportedRun=cpu;
    const ready=info.capabilities.cuda?.ready===true||info.capabilities.cuda?.available===true;
    if(options.cuda==='required')check('CUDA is available for the required hardware comparison',ready);
    if(options.cuda!=='off'&&ready){
      const gpu=await runPage('cuda');exportedRun=gpu;
      const ranked=run=>run.candidates.map(c=>[c.plaintext,c.score_exact,c.assignment_index_decimal]);
      check('CPU and certified CUDA return the identical page ranking',JSON.stringify(ranked(cpu))===JSON.stringify(ranked(gpu)));
    }else{skips.push({check:'CUDA page comparison',reason:options.cuda==='off'?'explicitly disabled':'CUDA unavailable; CPU checks only'});}
    const downloadPromise=page.waitForEvent('download');await page.locator('#export-button').click();
    const downloaded=await downloadPromise;const exportFile=path.join(out,'downloaded-run.json');await downloaded.saveAs(exportFile);
    const exported=JSON.parse(fs.readFileSync(exportFile,'utf8'));assertNoManagedControls(exported);
    check('UI download exports the displayed run with no managed path controls',exported.id===exportedRun.id);
    await page.locator('[data-view="inspector"]').click();await page.locator('#import-file').setInputFiles(exportFile);
    await page.waitForFunction(()=>document.getElementById('import-json').value.length>0);
    await page.locator('#inspect-import').click();await page.waitForFunction(()=>!document.getElementById('inspection-panel').hidden);
    check('Downloaded run freshly replays after file import',await page.locator('#inspection-title').textContent()==='Recipe and clues agree.');
    save('download-inspection.json',JSON.parse(await page.locator('#inspection-json').textContent()));await shot('desktop-export-replay');
    const step=exported.candidates[0].encryption_recipe.stages.find(s=>s.operation==='repeat_substitution');assert(step);
    step.key_pattern=(step.key_pattern[0]==='A'?'B':'A')+step.key_pattern.slice(1);
    await page.locator('#import-json').fill(JSON.stringify(exported));await page.locator('#inspect-import').click();
    await page.waitForFunction(()=>!document.getElementById('inspection-panel').hidden);
    const rejected=JSON.parse(await page.locator('#inspection-json').textContent());
    check('A tampered exported key fails independent literal replay',rejected.valid===false&&rejected.reencryption_matches===false);
    save('tampered-inspection.json',rejected);
  }
  check('No browser JavaScript errors',errors.length===0);
  const status=await get('/api/status');
  check('Validation leaves no active test computation',!['running','pausing','stopping'].includes(status.run?.state)&&!['running','pausing','stopping'].includes(status.campaign?.state));
  evidence.finished_at=new Date().toISOString();evidence.checks=checks;evidence.passed=checks.length;
  evidence.errors=errors;evidence.run_ids=runIds;evidence.requests=requests;evidence.skipped=skips;
  evidence.scope='Actual local server browser checks with synthetic CPU controls and optional actual CUDA comparison; no reserved multilingual bank rerun. Scores and fits are not authentication.';
  save('browser-report.json',evidence);console.log(JSON.stringify({passed:checks.length,errors,skipped:skips}));
 } catch(error) {
  const cleanupResult=await cleanup();
  let status;try{status=await get('/api/status');}catch(_){status=null;}
  save('browser-failure.json',{...evidence,message:error.message,checks,errors,runIds,requests,skips,cleanup:cleanupResult,status});
  if(page)try{await shot('failure');}catch(_){}
  throw error;
 } finally {
  if(browser)await browser.close();
  const index={};for(const name of fs.readdirSync(out)){
    const file=path.join(out,name);if(fs.statSync(file).isFile())index[name]={bytes:fs.statSync(file).size,sha256:sha256(fs.readFileSync(file))};
  }
  save('files.json',index);
 }
}

async function main(argv=process.argv.slice(2)) {
 const options=parseOptions(argv);
 if(options.help){console.log(`Usage: node research/browser_validation.cjs --url http://127.0.0.1:8768/ --out NEW_DIRECTORY [options]

The existing server must be a dedicated, freshly started local validation instance.
This runner creates synthetic runs and stops only its own active jobs on failure.
It never starts a server or writes to an existing evidence directory.

  --suite n|devices|all         Default: all
  --cuda off|auto|required     Default: auto; required fails if CUDA is unavailable
  --timeout-ms 90000           Maximum wait per workflow (5000..300000)
  --playwright-module PATH     Explicit module, or PLAYWRIGHT_MODULE; otherwise installed playwright/playwright-core
  --browser-executable PATH    Explicit executable, or CHROME_PATH / CHROMIUM_PATH

Installed Chrome/Chromium/Edge or Playwright's bundled browser is used. No downloads.
Output includes JSON exports, screenshots, assertions, source hashes and a file index.
Control tokens and HTTP headers are not recorded.`);return;}
 await run(options);
}

module.exports={parseOptions,redact,assertNoManagedControls,browserExecutable};
if(require.main===module)main().catch(error=>{console.error(error.stack||error);process.exitCode=1;});
