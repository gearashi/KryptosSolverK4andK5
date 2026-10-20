const {chromium}=require('C:/Users/there/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/node_modules/playwright');
const fs=require('fs'),assert=require('assert');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe'});
 const page=await browser.newPage({viewport:{width:1440,height:1080}});await page.emulateMedia({reducedMotion:'reduce'});
 const errors=[],requests=[];page.on('pageerror',e=>errors.push(e.message));page.on('request',r=>{if(r.method()==='POST')requests.push(r.url());});
 const checks=[];const check=(name,value)=>{assert(value,name);checks.push(name);};
 const screenshot=async(name)=>{await page.evaluate(()=>{document.activeElement.blur();window.scrollTo({top:0,behavior:'instant'});});await page.screenshot({path:`runtime/ui-next/screenshots/${name}.png`,fullPage:true});};
 try{
  await page.goto('http://127.0.0.1:8768/');await page.waitForFunction(()=>!document.getElementById('start-button').disabled);
  check('Idle K4 source has97 letters',await page.locator('.cipher-cell').count()===97);
  check('No search starts on page load',requests.length===0);await screenshot('desktop-workbench');
  await page.locator('[data-view="campaigns"]').click();await page.locator('#campaign-use-workbench').click();await page.locator('#preview-campaign').click();await page.waitForFunction(()=>!document.getElementById('start-campaign').disabled);
  check('Explicit campaign preview shows two jobs',(await page.locator('#campaign-preview tbody tr').count())===2);
  await screenshot('desktop-campaign');await page.locator('#campaign-name').fill('Changed matrix name');check('Editing invalidates launch preview',await page.locator('#start-campaign').isDisabled());
  await page.locator('[data-view="validation"]').click();check('Validation presets available',await page.locator('#validation-preset option').count()===2);await screenshot('desktop-validation');
  await page.locator('[data-view="inspector"]').click();
  const artifact={schema:'kryptos.candidate-export.v1',request:{target:'custom',ciphertext:'BDFDHF',cribs:[{start:2,text:'BC'}]},candidate:{plaintext:'ABCDEF',encryption_recipe:{schema:'kryptos.encryption-recipe.v1',alphabet:'standard',stages:[{operation:'repeat_substitution',cipher:'vigenere',key_pattern:'BC'},{operation:'gather',permutation:[0,2,3,1,5,4]}]}}};
  await page.locator('#import-json').fill(JSON.stringify(artifact));await page.locator('#inspect-import').click();await page.waitForFunction(()=>!document.getElementById('inspection-panel').hidden);
  check('Literal independent replay succeeds',(await page.locator('#inspection-title').textContent()).includes('agree.'));
  await page.locator('#trace-source .trace-cell').nth(1).click();check('Non-involutive trace follows B into output4',(await page.locator('#trace-stages .trace-stage').nth(1).locator('.trace-stage-heading').textContent()).includes('2 → 4'));
  const selected=page.locator('#trace-source .trace-cell').nth(1);await selected.focus();await page.keyboard.press('ArrowRight');check('Trace keyboard selection moves to original3',(await page.locator('#trace-position').textContent()).includes('ORIGINAL 3 / 6'));
  await screenshot('desktop-inspector');await page.setViewportSize({width:390,height:844});await screenshot('mobile-inspector');check('Inspector mobile has no document overflow',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  for(const view of ['campaigns','validation','workbench']){await page.locator(`[data-view="${view}"]`).click();await screenshot(`mobile-${view}`);check(`${view} mobile has no document overflow`,await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));}
  await page.locator('[data-view="inspector"]').click();artifact.candidate.encryption_recipe.stages[0].key_pattern='BD';artifact.candidate.evidence={literal_reencryption_matches:true};await page.locator('#import-json').fill(JSON.stringify(artifact));await page.locator('#inspect-import').click();await page.waitForFunction(()=>document.getElementById('inspection-title').textContent.includes('does not agree'));check('Saved success does not override tampered recipe',true);
  check('No run started during preview/import checks',!requests.some(u=>/api\/(start|campaigns\/start)$/.test(u)));check('No JavaScript errors',errors.length===0);
  const report={checks,errors,requests};fs.writeFileSync('runtime/ui-next/idle-import-report.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1});
