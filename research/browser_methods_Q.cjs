'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {parseOptions,browserExecutable,redact}=require('./browser_validation.cjs');
async function main(){
 const options=parseOptions(process.argv.slice(2));
 const {chromium}=require(options.playwrightModule||process.env.PLAYWRIGHT_MODULE||'playwright');
 fs.mkdirSync(options.out,{recursive:false});const checks=[],errors=[];let browser,page;
 const save=(name,value)=>fs.writeFileSync(path.join(options.out,name),JSON.stringify(redact(value),null,2)+'\n',{flag:'wx'});
 const check=(name,value)=>{assert(value,name);checks.push(name);console.log('PASS '+name);};
 try{
  browser=await chromium.launch({headless:true,executablePath:browserExecutable(options)});
  page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
  await page.goto(options.url);await page.waitForFunction(()=>document.getElementById('methods-example').options.length>=3);
  const get=async url=>(await page.request.get(new URL(url,options.url).href)).json();
  const info=await get('/api/info');check('Opening the dashboard leaves computation idle',(await get('/api/status')).run===null);
  check('Worker selector exposes all detected logical processors within cap',await page.locator('#workers option').count()===info.capabilities.workers_max);
  check('Live worker selector has the same hardware capacity',await page.locator('#resource-workers option').count()===info.capabilities.workers_max);
  await page.locator('[data-view="methods"]').click();
  check('Research methods tab opens',await page.locator('#methods-view').isVisible());
  check('The complete 90-item ledger is shown',await page.locator('#methods-ledger li').count()===90);
  const catalog=await get('/api/methods');let previous=null;
  for(const command of ['constraint-lab','factor-lab','model-lab','grammar-lab']){
   const example=catalog.examples.find(e=>e.command===command);assert(example,'example for '+command);
   await page.locator('#methods-example').selectOption(example.id);
   check(command+' example loads its exact engine',await page.locator('#methods-command').inputValue()===command);
   await page.locator('#methods-start').click();
   const deadline=Date.now()+40000;let run;
   while(Date.now()<deadline){run=(await get('/api/status')).run;if(run&&run.id!==previous&&!['running','pausing','stopping'].includes(run.state))break;await page.waitForTimeout(150);}
   check(command+' managed experiment completes',run?.id!==previous&&run?.state==='completed');previous=run.id;
   check(command+' preserves its declared request',JSON.stringify(run.request)===JSON.stringify(example.request));
   check(command+' result is not presented as a Kryptos solution',run.result.authenticated_solution===false&&run.result.candidates.length===0);
   await page.waitForFunction(id=>{try{return document.getElementById('methods-status').textContent.includes('completed')&&JSON.parse(document.getElementById('methods-result').textContent).command===id;}catch{return false;}},command);
   save(command+'.json',run);
  }
  await page.locator('[data-view="workbench"]').click();
  check('Leaving methods hides its view',!await page.locator('#methods-view').isVisible());
  await page.locator('#preset').selectOption('demo-optimize');await page.locator('#factor-strategies-Q').evaluate(d=>d.open=true);
  for(const [key,value] of [['ordering','strong'],['decomposition','junction'],['elimination_bound','overlap']]){
   await page.locator('#field-'+key).selectOption(value);
   check('Optimizer '+key+' writes selected strategy',JSON.parse(await page.locator('#recipe-json').inputValue())[key]===value);
  }
  await page.locator('#preset').selectOption('joint-ranked');await page.locator('#joint-strategies').evaluate(d=>d.open=true);
  await page.locator('#field-propagation').selectOption('relational');
  check('Joint relational propagation is selectable',JSON.parse(await page.locator('#recipe-json').inputValue()).propagation==='relational');
  await page.locator('[data-view="methods"]').click();await page.locator('#methods-result').evaluate(e=>e.closest('details').open=true);
  await page.screenshot({path:path.join(options.out,'methods-desktop.png'),fullPage:true});
  await page.setViewportSize({width:390,height:844});
  check('Research methods fits a mobile viewport',await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1));
  await page.screenshot({path:path.join(options.out,'methods-mobile.png'),fullPage:true});
  check('No JavaScript errors',errors.length===0);
  check('No active computation remains',!['running','pausing','stopping'].includes((await get('/api/status')).run?.state));
  save('report.json',{schema:'kryptos.browser-methods-Q.v1',passed:checks.length,checks,errors,version:info.version,script_sha256:crypto.createHash('sha256').update(fs.readFileSync(__filename)).digest('hex')});
 }catch(error){save('failure.json',{message:error.message,checks,errors});if(page)await page.screenshot({path:path.join(options.out,'failure.png'),fullPage:true});throw error;}finally{if(browser)await browser.close();}
}
main().catch(error=>{console.error(error.stack||error);process.exitCode=1;});
