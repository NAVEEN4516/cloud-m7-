/* Review 2: explicit dataset identity, local assets and original evidence. */
'use strict';
const $ = id => document.getElementById(id);
let analysis = null, network = null, reduced = false, requestSerial = 0, sqlSerial = 0;
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
function table(id, columns, rows) {
  $(id).innerHTML = rows.length ? `<table><thead><tr>${columns.map(c=>`<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${row.map(x=>`<td>${esc(typeof x === 'object' ? JSON.stringify(x) : x)}</td>`).join('')}</tr>`).join('')}</tbody></table>` : '<p style="padding:14px">No matching events or results.</p>';
}
function busy(active) {
  for (const id of ['reload','upload','run-sql','dataset','download-events','download-script']) $(id).disabled = active;
  if (active) { $('notice').textContent='Validating evidence and building analysis…'; $('error').hidden=true; }
}
function fail(error) { $('error').textContent=error.message; $('error').hidden=false; }
async function request(url, options) {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok || data.status === 'error') throw new Error((data.errors || [data.message || 'Request failed']).join('\n'));
  return data;
}
function clearSql() { ++sqlSerial; $('sql-result').innerHTML=''; $('sql-status').textContent='Run a query for the current dataset.'; }
async function load(force=false) {
  const serial=++requestSerial;
  clearSql(); busy(true);
  try {
    const data=await request(`/api/analyze?dataset=${encodeURIComponent($('dataset').value)}&force=${force}`);
    if (serial===requestSerial) populate(data);
  } catch(e) { if(serial===requestSerial) { analysis=null; fail(e); $('notice').textContent='Analysis unavailable. Select valid evidence and retry.'; } }
  finally { if(serial===requestSerial) busy(false); }
}
function populate(data) {
  analysis=data; clearSql();
  const s=data.summary, r=data.reduction;
  $('event-count').textContent=s.total_events;
  $('labels-count').textContent=`${s.attack_events_count} attack-labelled / ${s.total_events-s.attack_events_count} normal`;
  $('reduced-count').textContent=r.reduced_nodes;
  $('reduction-pct').textContent=`${r.node_reduction_pct}% fewer graph nodes`;
  $('sensor-count').textContent=data.novelty2_chokepoints.originating_sensors.length;
  $('flow-count').textContent=s.cross_tier_flows;
  $('notice').textContent=`${data.dataset_provenance.description} · ${data.dataset_provenance.source}`;
  $('dataset-id').textContent=`Dataset: ${data.dataset_id.slice(0,19)}…`;
  $('dataset-id').title=data.dataset_id;
  $('processing-time').textContent=`Analysis: ${data.processing_time_ms} ms ${data.from_cache ? '(cached run)' : '(measured)'}`;
  $('reduction-result').textContent=`${r.original_nodes} → ${r.reduced_nodes} nodes · ${r.original_edges} → ${r.reduced_edges} edges · ${r.folded_groups} folded group(s) · ${r.execution_time_ms} ms measured · Reachability ${r.source_target_reachability_preserved ? 'PRESERVED' : 'FAILED'}`;
  $('folds').replaceChildren();
  for(const [id,records] of Object.entries(data.folded_evidence)) {
    const b=document.createElement('button'); b.className='fold'; b.textContent=`Expand ${records.length} identical reads`; b.onclick=()=>inspect(id); $('folds').append(b);
  }
  if(!Object.keys(data.folded_evidence).length) $('folds').textContent='No eligible repeated-read chains. Evidence remains unchanged.';
  $('evidence-title').textContent='Select a node'; $('evidence').textContent='No node selected.';
  table('events-table',['UUID','Tier','Host','Type','Action','Entity','Supplied label'],data.events.map(e=>[e.uuid,e.tier,e.host_id,e.event_type,e.payload.action,e.payload.entity || (e.payload.dst_ip ? `${e.payload.src_ip}:${e.payload.src_port} → ${e.payload.dst_ip}:${e.payload.dst_port}` : ''),e.payload.is_attack ? 'Attack':'Normal']));
  $('paths-summary').textContent=s.path_length ? `${s.path_length} events in the primary path · ${s.noise_reduction_pct}% of original nodes excluded from this single path (not graph compression)` : 'No attack-labelled incident in this input. No attack path claimed.';
  table('timeline',['Step','Tier','Host','Action','Evidence'],data.reconstructed_timeline.map(e=>[e.order,e.tier,e.host_id,e.action,e.entity]));
  table('vectors',['Entry host','Entry event','Path events','Impact score'],data.novelty1_iterative.vectors.map(v=>[v.entry_host,v.entry_entity,v.path_length,v.impact_score]));
  $('sensors').innerHTML=data.novelty2_chokepoints.originating_sensors.map(h=>`<span class="chip">${esc(h)}</span>`).join('') || '<p>No attack source identified.</p>';
  table('chokes',['Host','Action','Paths through node','Calculated containment'],data.novelty2_chokepoints.choke_points.map(c=>[c.host_id,c.action,`${c.paths_severed} / ${c.total_paths}`,`${c.containment_efficiency_pct}%`]));
  const p=data.placement;
  const metrics=[['Estimated latency (ms)','latency_ms'],['Estimated bandwidth (KB/s)','bandwidth_kbps'],['Privacy penalty (model points)','privacy_risk_score'],['Estimated cost ($/day)','monetary_cost_usd_per_day'],['Model edge CPU (mcores)','edge_cpu_used_mcore'],['Model edge memory (MB)','edge_mem_used_mb'],['Weighted objective J','total_cost_j'],['Capacity feasible','is_feasible']];
  table('placement-table',['Model metric','Centralized estimate','Adaptive estimate'],metrics.map(([label,key])=>[label,p.centralized[key],p.adaptive[key]]));
  $('assignment').innerHTML=Object.entries(p.assignment).map(([task,tier])=>`<span class="chip">${esc(task)} → ${esc(tier)}</span>`).join('');
  $('placement-assumptions').textContent=JSON.stringify(p.assumptions,null,2);
  const storage=data.parquet_storage;
  $('storage-results').innerHTML=[`Original JSON: ${storage.raw_json_bytes} bytes`,`Parquet: ${storage.parquet_bytes} bytes`,`JSON/Parquet ratio: ${storage.compression_ratio}×`,`Storage query: ${storage.query_latency_ms} ms`].map(x=>`<span class="chip">${esc(x)}</span>`).join('');
  $('bridge-results').textContent=JSON.stringify(data.novelty3_causal_bridge,null,2);
  $('mitre-results').textContent=data.novelty5_mitre.summary_text;
  $('remediation-results').textContent=data.novelty4_remediation.deployment_script;
  draw();
}
function inspect(id) {
  if(!analysis) return;
  const records=analysis.folded_evidence[id] || analysis.events.filter(e=>e.uuid===id);
  $('evidence-title').textContent=records.length>1 ? `${records.length} original events` : 'Original event';
  $('evidence').textContent=JSON.stringify(records,null,2);
}
function draw() {
  if(!analysis) return;
  if(network) network.destroy();
  const graph=reduced ? analysis.reduced_graph : analysis.graph;
  if(!window.vis) { fail(new Error('Local graph library missing. Run setup_demo.ps1.')); return; }
  network=new vis.Network($('graph'),{nodes:graph.nodes.map(n=>({...n,title:esc(n.title),font:{color:'#e1edf7',size:11},borderWidth:1,shape:'dot'})),edges:graph.edges.map(e=>({...e,arrows:'to',color:e.color || '#68859b'}))},{layout:{randomSeed:42},physics:{solver:'barnesHut',stabilization:{iterations:200}},interaction:{hover:true},edges:{smooth:{type:'continuous'},width:1.2},nodes:{shadow:false}});
  network.on('click',({nodes})=>{if(nodes.length)inspect(nodes[0]);});
  network.once('stabilizationIterationsDone',()=>network.setOptions({physics:false}));
}
function setView(value) { reduced=value; $('original').classList.toggle('selected',!value); $('reduced').classList.toggle('selected',value); $('original').setAttribute('aria-pressed',!value); $('reduced').setAttribute('aria-pressed',value); draw(); }
function download(name,text,type='application/json') {
  const link=document.createElement('a'); const url=URL.createObjectURL(new Blob([text],{type})); link.href=url; link.download=name; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function upload() {
  const file=$('file').files[0]; if(!file) {fail(new Error('Select an evidence file first.'));return;}
  const serial=++requestSerial; clearSql(); busy(true);
  try {
    const body=new FormData(); body.append('dataset_file',file);
    const data=await request('/api/upload',{method:'POST',body});
    if(serial!==requestSerial)return;
    let option=Array.from($('dataset').options).find(x=>x.value===data.dataset_id);
    if(!option) {option=new Option(`Uploaded: ${file.name}`,data.dataset_id);$('dataset').add(option);}
    option.textContent=`Uploaded: ${file.name}`; $('dataset').value=data.dataset_id; populate(data);
  } catch(e) {if(serial===requestSerial) {fail(e);$('notice').textContent='Upload rejected. Previous valid evidence remains selected.';}}
  finally {if(serial===requestSerial)busy(false);}
}
async function sql() {
  if(!analysis)return;
  const id=analysis.dataset_id, serial=++sqlSerial;
  $('run-sql').disabled=true; $('sql-status').textContent='Querying selected dataset…';
  try {
    const data=await request('/api/sql',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({dataset_id:id,query:$('query').value})});
    if(serial!==sqlSerial || analysis?.dataset_id!==id)return;
    table('sql-result',data.columns,data.rows.map(row=>data.columns.map(c=>row[c])));
    $('sql-status').textContent=`${data.row_count} row(s) · ${data.latency_ms} ms measured`;
  }catch(e){if(serial===sqlSerial){$('sql-result').replaceChildren();$('sql-status').textContent=e.message;}}
  finally{if(serial===sqlSerial)$('run-sql').disabled=false;}
}
for(const button of document.querySelectorAll('.nav')) button.addEventListener('click',()=>{
  document.querySelectorAll('.nav').forEach(b=>b.classList.toggle('active',b===button));
  document.querySelectorAll('.panel').forEach(p=>p.hidden=p.id!==`panel-${button.dataset.panel}`);
  if(button.dataset.panel==='graph' && network)network.fit();
});
$('dataset').addEventListener('change',()=>load()); $('reload').addEventListener('click',()=>load(true));
$('upload').addEventListener('click',upload); $('original').addEventListener('click',()=>setView(false)); $('reduced').addEventListener('click',()=>setView(true)); $('fit').addEventListener('click',()=>network?.fit());
$('run-sql').addEventListener('click',sql); $('count-sql').addEventListener('click',()=>{$('query').value='SELECT COUNT(*) AS event_count FROM provenance';});
$('download-events').addEventListener('click',()=>{if(analysis)download('cloud-m7-evidence.json',JSON.stringify(analysis.events,null,2));});
$('download-script').addEventListener('click',()=>{if(analysis)download('proposed-containment.sh',analysis.novelty4_remediation.deployment_script,'text/plain');});
load();
