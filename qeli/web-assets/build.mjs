// Pinned public compiler APIs; each watch build gets a fresh module/cache state.
import fs from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {randomUUID} from 'node:crypto';
import {spawn} from 'node:child_process';
import {compile,optimize} from '@tailwindcss/node';
import {Scanner} from '@tailwindcss/oxide';
import {watchBuild} from './watch.mjs';

const script=fileURLToPath(import.meta.url),base=path.dirname(script);
const input=path.join(base,'input.css'),output=path.resolve(base,'../src/web/assets/app.css'),receipt=path.join(base,'.css-build.json');
let watchedDependencies=[];
const args=process.argv.slice(2);
if(args.length&&!(args.length===1&&['--once','--watch'].includes(args[0])))throw Error('Expected --once or --watch');

async function buildOnce() {
  const dependencies=new Set();
  try {
  const compiler=await compile(await fs.readFile(input,'utf8'),{
    base,from:input,onDependency:file=>dependencies.add(file),shouldRewriteUrls:true,
    // Observe relative CSS lookup attempts even when the compiler cannot resolve
    // them yet. Return undefined so its normal resolver and compiler stay in charge.
    async customCssResolver(id,importerBase) {
      if(id.startsWith('.')||path.isAbsolute(id)||id.endsWith('.css')) {
        const attempt=path.resolve(importerBase,id);dependencies.add(attempt);
        if(!path.extname(attempt))dependencies.add(attempt+'.css');
      }
      return undefined;
    },
  });
  if(compiler.root!=='none')throw Error('Only explicitly declared template sources are permitted');
  const scanner=new Scanner({sources:compiler.sources});const candidates=scanner.scan();
  const result=optimize(compiler.build(candidates),{file:input,minify:true});
  const metadata={status:'PROGRAMMATIC_CSS_PROTOTYPE_BUILT',
    candidates:candidates.length,files:scanner.files,sources:compiler.sources,dependencies:[...dependencies].sort(),
    no_CLI:true,no_third_party_watcher:true,adopted:false};
  const temporary=output+'.'+randomUUID()+'.tmp',temporaryReceipt=receipt+'.'+randomUUID()+'.tmp';
  try {
    await fs.writeFile(temporary,result.code,{flag:'wx'});
    await fs.writeFile(temporaryReceipt,JSON.stringify(metadata,null,2)+'\n',{flag:'wx'});
    await fs.rename(temporaryReceipt,receipt);
    await fs.rename(temporary,output);
  } finally {
    for(const file of [temporary,temporaryReceipt])await fs.unlink(file).catch(error=>{if(error.code!=='ENOENT')throw error;});
  }
  console.log('PROGRAMMATIC_CSS_PROTOTYPE_BUILT',candidates.length,'candidates');
  if(process.connected){process.send({type:'compiled',dependencies:metadata.dependencies});process.disconnect();}
  } catch(error) {
    // Diagnostics files remain optional. Failed lookup attempts reach the parent
    // over IPC so creation/restoration of those files can recover watch mode.
    if(process.connected){process.send({type:'build-failed',dependencies:[...dependencies].sort()});process.disconnect();}
    throw error;
  }
}

function freshBuild(signal) {
  return new Promise((resolve,reject)=>{
    let metadata;
    const child=spawn(process.execPath,[script,'--once'],{cwd:base,stdio:['inherit','inherit','inherit','ipc'],windowsHide:true,signal});
    child.on('message',message=>{if(['compiled','build-failed'].includes(message?.type)&&Array.isArray(message.dependencies)&&message.dependencies.every(name=>typeof name==='string'))metadata=message;});
    child.once('error',reject);
    child.once('close',(code,termination)=>{
      if(code!==0) {
        if(metadata)watchedDependencies=[...new Set([...watchedDependencies,...metadata.dependencies])];
        return reject(Error(`Compiler exited ${code}/${termination}`));
      }
      if(!metadata)return reject(Error('Compiler completed without dependency metadata'));
      watchedDependencies=metadata.dependencies;resolve();
    });
  });
}

if(args[0]==='--watch') {
  const controller=new AbortController();const stop=()=>controller.abort();
  process.on('SIGINT',stop);process.on('SIGTERM',stop);
  // IPC is only used by the isolated integration harness for orderly shutdown.
  process.on('message',message=>{if(message==='stop')stop();});
  try {
    await watchBuild({signal:controller.signal,build:freshBuild,inputs:async()=>{
      return {files:[input,path.join(base,'tailwind.config.js'),...watchedDependencies.filter(name=>!name.split(/[\\/]/).includes('node_modules'))],
        directories:[path.resolve(base,'../src/web/templates')]};
    },onEvent:event=>{console.log('CSS_WATCH_EVENT',JSON.stringify(event));if(process.connected)process.send(event);}});
  } finally { process.off('SIGINT',stop);process.off('SIGTERM',stop);if(process.connected)process.disconnect(); }
} else await buildOnce();
