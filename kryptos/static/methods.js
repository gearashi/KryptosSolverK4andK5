"use strict";
(() => {
  const $=id=>document.getElementById(id);
  let api, examples=[], current=null, timer=null, busy=false;
  const show=run=>{
    current=run;
    $("methods-status").textContent=`${run.command} · ${run.state}${run.error?` · ${run.error}`:""}`;
    $("methods-result").textContent=JSON.stringify(run.result||{state:run.state},null,2);
    const active=["running","pausing","stopping"].includes(run.state);
    $("methods-stop").disabled=!active;
    $("methods-start").disabled=active||busy;
    clearTimeout(timer);
    if(active)timer=setTimeout(poll,750);
  };
  async function poll(){if(!current)return;try{show((await api(`/api/runs/${current.id}`)).run);}catch(error){$("methods-status").textContent=error.message;timer=setTimeout(poll,2000);}}
  function loadExample(){const example=examples.find(e=>e.id===$("methods-example").value);if(!example)return;$("methods-command").value=example.command;$("methods-request").value=JSON.stringify(example.request,null,2);}
  document.addEventListener("kryptos-ready",async event=>{
    api=event.detail.api;
    try{
      const data=await api("/api/methods");examples=data.examples||[];
      $("methods-policy").textContent=data.interpretation;
      $("methods-example").replaceChildren(...examples.map(example=>{const option=document.createElement("option");option.value=example.id;option.textContent=example.label;return option;}));
      $("methods-ledger").replaceChildren(...data.entries.map(entry=>{const item=document.createElement("li");item.textContent=`${entry.title} — ${entry.status}${entry.scope?`: ${entry.scope}`:""}`;return item;}));
      loadExample();$("methods-start").disabled=false;
      const status=await api("/api/status");if(status.run?.command?.endsWith("-lab"))show(status.run);
    }catch(error){$("methods-status").textContent=error.message;}
  });
  $("methods-example").addEventListener("change",loadExample);
  $("methods-start").addEventListener("click",async()=>{
    if(busy)return;busy=true;$("methods-start").disabled=true;
    try{const request=JSON.parse($("methods-request").value);const response=await api("/api/start",{kind:"exact",command:$("methods-command").value,request,backend:"cpu",workers:1,note:"Explicit bounded research model; see original request and technique trace."});show(response.run);}catch(error){$("methods-status").textContent=error.message;}finally{busy=false;if(!current||!["running","pausing","stopping"].includes(current.state))$("methods-start").disabled=false;}
  });
  $("methods-stop").addEventListener("click",async()=>{if(!current)return;try{show((await api("/api/stop",{run_id:current.id})).run);}catch(error){$("methods-status").textContent=error.message;}});
})();
