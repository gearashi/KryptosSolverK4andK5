"use strict";
(() => {
  const $=id=>document.getElementById(id);
  let api, batteries=[], timer=null, busy=false;
  const cell=(tag,text)=>{const e=document.createElement(tag);e.textContent=text;return e;};
  const describe=()=>{const b=batteries.find(x=>x.id===$("exact-battery").value);$("exact-description").textContent=b?`${b.description} Typical time: about ${b.typical_seconds} s.`:"";};
  const summary=result=>{
    const table=document.createElement("table");table.className="evidence-table";
    const head=document.createElement("tr");for(const h of ["Settings tested","Decidable","Survivors","Seconds"])head.append(cell("th",h));
    const row=document.createElement("tr");for(const v of [result.tested,result.decidable,result.survivor_count,result.seconds])row.append(cell("td",String(v)));
    table.append(head,row);
    const list=document.createElement("ol");for(const s of (result.survivors||[]).slice(0,50))list.append(cell("li",`${s.model}${s.key?` · key ${s.key}`:""}${s.residual!==undefined?` · ${s.residual} clue letters left over`:""}`));
    const verdict=cell("p",result.stopped?"Stopped early: only part of this family was tested, so nothing is excluded.":result.survivor_count?"Survivors fit the clue letters. A survivor is a family to examine, not a solution.":"No setting of this family fits the clue letters under the stated assumptions.");verdict.className="field-help";
    $("exact-summary").replaceChildren(table,verdict,list);
  };
  const show=run=>{
    const active=run.state==="running";
    $("exact-status").textContent=run.battery?`${run.battery} · ${run.state}${run.error?` · ${run.error}`:""}`:"Choose a battery; no computation starts automatically.";
    $("exact-result").textContent=run.result?JSON.stringify(run.result,null,2):"";
    if(run.result)summary(run.result);else if(active)$("exact-summary").replaceChildren();
    $("exact-stop").disabled=!active;$("exact-start").disabled=active||busy;
    clearTimeout(timer);if(active)timer=setTimeout(poll,750);
  };
  async function poll(){try{show((await api("/api/exact-tests")).run);}catch(error){$("exact-status").textContent=error.message;timer=setTimeout(poll,2000);}}
  document.addEventListener("kryptos-ready",async event=>{
    api=event.detail.api;
    try{
      const data=await api("/api/exact-tests");batteries=data.batteries||[];
      $("exact-policy").textContent=data.interpretation;$("exact-assumptions").textContent=data.assumptions;
      $("exact-battery").replaceChildren(...batteries.map(b=>{const o=document.createElement("option");o.value=b.id;o.textContent=b.title;return o;}));
      describe();$("exact-start").disabled=false;show(data.run);
    }catch(error){$("exact-status").textContent=error.message;}
  });
  $("exact-battery").addEventListener("change",describe);
  $("exact-start").addEventListener("click",async()=>{
    if(busy)return;busy=true;$("exact-start").disabled=true;
    try{const request={battery:$("exact-battery").value};const cipher=$("exact-cipher").value.trim();if(cipher)request.cipher=cipher;show((await api("/api/exact-tests/start",request)).run);}
    catch(error){$("exact-status").textContent=error.message;}
    finally{busy=false;if($("exact-stop").disabled)$("exact-start").disabled=false;}
  });
  $("exact-stop").addEventListener("click",async()=>{try{show((await api("/api/exact-tests/stop",{})).run);}catch(error){$("exact-status").textContent=error.message;}});
})();
