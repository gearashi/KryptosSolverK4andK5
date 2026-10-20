'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const path=require('node:path');
const {parseOptions,redact,assertNoManagedControls,browserExecutable}=require('../research/browser_validation.cjs');

test('fresh local validation options are portable and explicit',()=>{
 const value=parseOptions(['--url','http://localhost:8879/','--out','runtime/new-browser-evidence','--cuda','required','--suite','all']);
 assert.equal(value.url,'http://localhost:8879/');assert.equal(value.cuda,'required');
 assert.equal(value.out,path.resolve('runtime/new-browser-evidence'));assert.equal(value.timeoutMs,90000);
 assert.equal(parseOptions(['--url','http://[::1]:8778/','--out','new']).url,'http://[::1]:8778/');
});

test('runner refuses remote origins, credentials, user-app port and hidden paths',()=>{
 for(const url of ['https://example.com/','http://user:password@localhost:8778/','http://localhost:8767/',
   'file:///tmp/app','http://127.0.0.1:8778/private','http://localhost:8778/?token=secret','http://localhost:8778/#run']){
  assert.throws(()=>parseOptions(['--url',url,'--out','new']),undefined,url);
 }
});

test('invalid, incomplete and misleading options fail before browser launch',()=>{
 for(const args of [[],['--out'],['--unknown','value'],['--out','new','--cuda','yes'],
   ['--out','new','--suite','n','--cuda','required'],['--out','new','--timeout-ms','1'],
   ['--out','new','--timeout-ms','1.5'],['--out','new','--timeout-ms','NaN']])assert.throws(()=>parseOptions(args));
 assert.deepEqual(parseOptions(['--help']),{help:true});
});

test('evidence redaction preserves model and recipe data while removing credentials',()=>{
 const value={control_token:'secret',nested:[{Authorization:'secret',cookie:'secret',key_pattern:'BCD',model_path:'models/en.json'}]};
 const output=redact(value);assert.equal(output.control_token,'[REDACTED]');assert.equal(output.nested[0].Authorization,'[REDACTED]');
 assert.equal(output.nested[0].cookie,'[REDACTED]');assert.equal(output.nested[0].key_pattern,'BCD');
 assert.equal(output.nested[0].model_path,'models/en.json');assert.equal(value.control_token,'secret');
});

test('export audit finds executable managed controls at every nested depth',()=>{
 assert.doesNotThrow(()=>assertNoManagedControls({exact_checkpoint:{file:'metadata.json',sha256:'recorded'},request:{model_path:'models/en.json'}}));
 for(const key of ['checkpoint_path','resume_path','checkpoint_written'])assert.throws(()=>assertNoManagedControls({result:[{[key]:'unsafe'}]}));
});

test('explicit browser path is checked without launching a process',()=>{
 assert.equal(browserExecutable({browserExecutable:__filename},{}),path.resolve(__filename));
 assert.throws(()=>browserExecutable({browserExecutable:path.join(__dirname,'does-not-exist.exe')},{}),/does not exist/);
});
