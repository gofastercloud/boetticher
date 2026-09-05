'use strict';
const titles={overview:'Lab overview',core:'Core services',resources:'Proxmox resources',pi:'Companion health'};
function text(tag,value){const element=document.createElement(tag);element.textContent=value;return element;}
function render(snapshot){
 const view=snapshot.view;
 const module=(snapshot.modules||[]).find(item=>item.id===view);
 document.body.className=(snapshot.brightness==='normal'?'':snapshot.brightness)+' '+(!titles[view]&&!module?'detail':'');
 document.getElementById('title').textContent=titles[view]||module?.label||snapshot.items.find(item=>item.id===view)?.label||'Status';
 document.getElementById('updated').textContent='Updated '+new Date(snapshot.updated_at).toLocaleTimeString();
 let items=snapshot.items;
 if(module)items=module.checks||[module];
 else if(view==='overview'&&snapshot.leds?.length===8)items=snapshot.leds;
 else if(view==='core')items=items.filter(item=>['link','gateway','dns','proxmox','pulse'].includes(item.id)).concat((snapshot.modules||[]).filter(item=>item.status!=='disabled'));
 else if(view==='pi')items=items.filter(item=>['pi','link','agent','peripherals'].includes(item.id));
 else if(view==='resources')items=snapshot.resources.slice(snapshot.page*8,(snapshot.page+1)*8).map(resource=>({label:resource.name,status:resource.status,value:resource.type,reason:`CPU ${resource.cpu==null?'—':Math.round(resource.cpu)+'%'} · Memory ${resource.memory==null?'—':Math.round(resource.memory)+'%'}`,observed_at:resource.observed_at}));
 else if(view.startsWith('resource:')){const resource=snapshot.resources.find(item=>'resource:'+item.id===view);items=resource?[{label:resource.name,status:resource.status,value:resource.type,reason:`CPU ${resource.cpu==null?'—':Math.round(resource.cpu)+'%'} · Memory ${resource.memory==null?'—':Math.round(resource.memory)+'%'}`,observed_at:resource.observed_at}]:[];}
 else if(view!=='overview')items=items.filter(item=>item.id===view);
 const cards=document.getElementById('cards');cards.replaceChildren();
 for(const item of items){const card=text('article','');card.className='card '+item.status;card.append(text('h2',item.label),text('strong',item.value||item.status.toUpperCase()),text('p',item.status.toUpperCase()+' · '+item.reason));if(item.observed_at&&!item.observed_at.startsWith('0001'))card.append(text('p','Observed '+new Date(item.observed_at).toLocaleTimeString()));cards.append(card);}
 document.getElementById('description').textContent=view==='resources'?`Page ${snapshot.page+1} · ${snapshot.resources.length} resources`:'Select a StreamDeck tile for details';
 if(!items.length)document.getElementById('description').textContent='No resource data available yet';
 if(snapshot.leds)document.getElementById('legend').textContent='BLINKT · '+snapshot.leds.map((item,i)=>`${i+1} ${item.label}`).join(' · ');
}
async function update(){try{const response=await fetch('/api/status',{cache:'no-store'});if(!response.ok)throw Error('status');const snapshot=await response.json();render(snapshot);await fetch('/api/rendered',{method:'POST'});}catch{document.body.className='';document.getElementById('title').textContent='Companion connection lost';document.getElementById('description').textContent='Waiting for the local status service to return';document.getElementById('cards').replaceChildren();}finally{window.setTimeout(update,1000);}}
update();
