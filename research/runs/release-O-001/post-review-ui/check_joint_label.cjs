'use strict';
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const [url,out,modulePath,browserPath]=process.argv.slice(2);
const {chromium}=require(modulePath);const errors=[],checks=[];
const save=(name,data)=>fs.writeFileSync(path.join(out,name),JSON.stringify(data,null,2)+'\n',{flag:'wx'});
async function main(){let browser;try{
 browser=await chromium.launch({headless:true,executablePath:browserPath});const page=await browser.newPage({viewport:{width:1440,height:1000}});page.on('pageerror',e=>errors.push(e.message));
 await page.goto(url);await page.waitForFunction(()=>document.getElementById('preset').options.length>2);
 const get=async p=>(await page.request.get(new URL(p,url).href)).json();assert.equal((await get('/api/status')).run,null);checks.push('Isolated source dashboard opens idle');
 await page.locator('#preset').selectOption('joint-ranked');await page.locator('#advanced-settings').evaluate(d=>d.open=true);
 const request=JSON.parse(await page.locator('#recipe-json').inputValue());Object.assign(request,{max_states:32,max_evaluations:10,max_orders:10,top:3,time_limit_seconds:1});await page.locator('#recipe-json').fill(JSON.stringify(request,null,2));
 await page.locator('#start-button').click();let run;const deadline=Date.now()+15000;while(Date.now()<deadline){run=(await get('/api/status')).run;if(run&&!['running','pausing','stopping'].includes(run.state))break;await page.waitForTimeout(100);}
 assert(run&&run.state==='limited',JSON.stringify({state:run?.state,error:run?.error}));assert(run.exact_checkpoint?.states_total>0);assert(!Object.hasOwn(run.exact_checkpoint,'nodes_total'));checks.push('Tiny CPU joint job commits a states_total checkpoint');
 const expected=`slice ${run.exact_checkpoint.sequence} · ${new Intl.NumberFormat().format(run.exact_checkpoint.states_total)} search work steps`;
 await page.waitForFunction(t=>document.getElementById('result-summary').textContent.includes(t),expected);
 const label=await page.locator('#result-summary').textContent();assert(label.includes('Saved frontier: '+expected));assert(!label.includes('— nodes'));checks.push('Saved frontier displays the exact joint search-work count with its correct unit');
 assert.equal(errors.length,0);checks.push('No browser JavaScript errors');await page.locator('#result-summary').scrollIntoViewIfNeeded();await page.screenshot({path:path.join(out,'joint-checkpoint-label.png')});
 const served=await page.request.get(new URL('/static/app.js',url).href);
 save('browser-result.json',{schema:'kryptos.post-review-ui.v1',passed:checks.length,checks,errors,request,state:run.state,run_id:run.id,exact_checkpoint:run.exact_checkpoint,progress:run.progress,expected,label,served_app_js_sha256:crypto.createHash('sha256').update(await served.body()).digest('hex'),scope:'One bounded CPU joint job, maximum32 search work steps and10 scored completions. No full browser suite or GPU rerun.'});
 console.log(JSON.stringify({passed:checks.length,expected,state:run.state}));
 }catch(e){save('failure.json',{message:e.message,checks,errors});throw e;}finally{if(browser)await browser.close();}}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1;});
