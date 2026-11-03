// Small content poller for the repository's CSS build inputs. No glob/watch packages.
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {setTimeout as delay} from 'node:timers/promises';

export async function fingerprint({files,directories}) {
  const rows=[];
  async function file(name) {
    try { rows.push([name,createHash('sha256').update(await fs.readFile(name)).digest('hex')]); }
    catch(error) { if(error.code!=='ENOENT')throw error;rows.push([name,'MISSING']); }
  }
  async function directory(name) {
    let entries;
    try { entries=await fs.readdir(name,{withFileTypes:true}); }
    catch(error) { if(error.code!=='ENOENT')throw error;rows.push([name,'MISSING_DIRECTORY']);return; }
    for(const entry of entries.sort((a,b)=>a.name.localeCompare(b.name))) {
      const target=path.join(name,entry.name);
      if(entry.isDirectory())await directory(target);
      else if(entry.isFile()&&entry.name.endsWith('.html'))await file(target);
    }
  }
  for(const name of [...new Set(files)].sort())await file(name);
  for(const name of [...new Set(directories)].sort())await directory(name);
  return createHash('sha256').update(JSON.stringify(rows)).digest('hex');
}

export async function watchBuild({inputs,build,signal,interval=500,onEvent=()=>{}}) {
  let builds=0,failures=0,last;
  const attempt=async()=>{
    onEvent({type:'building',build:++builds});
    try { await build(signal);onEvent({type:'built',build:builds}); }
    catch(error) { if(signal.aborted)return;failures++;onEvent({type:'build-error',build:builds,error:String(error)}); }
  };
  // The first build is performed even when no file event arrives.
  last=await fingerprint(await inputs());await attempt();
  // Preserve changes made while compilation runs. New discovered imports can
  // also request one additional build; never absorb an uncompiled content change.
  onEvent({type:'ready',interval});
  while(!signal.aborted) {
    try { await delay(interval,undefined,{signal}); }
    catch(error) { if(error.name==='AbortError')break;throw error; }
    try {
      const current=await fingerprint(await inputs());
      if(current!==last) { last=current;await attempt(); }
    } catch(error) { onEvent({type:'input-error',error:String(error)}); }
  }
  onEvent({type:'stopped',builds,failures});return {builds,failures};
}
