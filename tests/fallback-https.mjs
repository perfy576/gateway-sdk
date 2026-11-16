import assert from 'node:assert/strict';
import https from 'node:https';
import {mkdtempSync,readFileSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {spawn,spawnSync} from 'node:child_process';
import {createHash,createHmac} from 'node:crypto';

const root=new URL('../',import.meta.url).pathname,temp=mkdtempSync(tmpdir()+'/gateway-sdk-tls-');
const secret='a'.repeat(64),verificationKey='b'.repeat(64),binding='v2.'+'c'.repeat(64),cookie='__Host-gateway_binding='+binding;
const issuer='https://gateway.example.com',audience='app.example.com',now=Math.floor(Date.now()/1000);
const claims={iss:issuer,aud:audience,sub:'1',sid:'d'.repeat(64),iat:now,nbf:now-2,exp:now+60,authenticated:true,
  username:'alice',display_name:'Alice',role:'user',ver:2,cookie_version:2};
const unsigned=Buffer.from(JSON.stringify({alg:'HS256',typ:'JWT',gwv:2})).toString('base64url')+'.'+Buffer.from(JSON.stringify(claims)).toString('base64url');
const token=unsigned+'.'+createHmac('sha256',secret).update(unsigned).digest('base64url');
const digest=x=>createHash('sha256').update(x).digest('hex');
const certificate=spawnSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',temp+'/key.pem','-out',temp+'/cert.pem','-days','1','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1,DNS:localhost'],{encoding:'utf8'});
assert.equal(certificate.status,0);
let calls=0;
const server=https.createServer({key:readFileSync(temp+'/key.pem'),cert:readFileSync(temp+'/cert.pem')},(req,res)=>{
  const chunks=[];req.on('data',c=>chunks.push(c));req.on('end',()=>{
    ++calls;if(req.url==='/redirect'){res.writeHead(302,{Location:'/verify'});res.end();return;}
    const data=JSON.parse(Buffer.concat(chunks));
    if(req.headers.authorization!=='Bearer '+verificationKey||data.token!==token||data.cookie!==cookie||data.method!=='GET'||data.uri!=='/future?x=1'||data.audience!==audience){res.writeHead(401);res.end('{}');return;}
    const response={valid:true,version:2,claims,token_sha256:digest(data.token),cookie_header_sha256:digest(data.cookie),request_method:data.method,request_uri_sha256:digest(data.uri)};
    if(req.url==='/mismatch')response.token_sha256='0'.repeat(64);
    res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify(response));
  });
});
await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;
function run(lang,changes={},expected=0){
  const data={issuer,audience,token,cookie,method:'GET',uri:'/future?x=1',mode:'auto',verify_url:`https://127.0.0.1:${port}/verify`,ca_file:temp+'/cert.pem',...changes};
  return new Promise((resolve,reject)=>{
    const child=spawn(lang==='python'?root+'.venv/bin/python':root+'build/gateway-sdk-verify',lang==='python'?[root+'python3-sdk/examples/verify.py']:[],{
      env:{...process.env,GATEWAY_TOKEN_SECRET:secret,GATEWAY_VERIFICATION_KEY:verificationKey},stdio:['pipe','pipe','pipe']});
    let out='',err='';child.stdout.on('data',c=>out+=c);child.stderr.on('data',c=>err+=c);child.on('error',reject);child.on('close',code=>{try{assert.equal(code,expected,`${lang}: ${err}`);resolve(out?JSON.parse(out):null);}catch(e){reject(e);}});child.stdin.end(JSON.stringify(data));
  });
}
try{
  for(const lang of ['python','cpp']){
    const result=await run(lang);assert.equal(result.verification,'online');assert.equal(result.claims.ver,2);
    await run(lang,{mode:'local'},4);
    const before=calls;await run(lang,{verify_url:`https://127.0.0.1:${port}/redirect`},3);assert.equal(calls,before+1);
    await run(lang,{verify_url:`https://127.0.0.1:${port}/mismatch`},3);
    await run(lang,{ca_file:''},3);
  }
  console.log('PASS both SDKs successfully fall back for a future v2 token/cookie over certificate-verified HTTPS; local-only rejection, redirect refusal, response binding and untrusted certificates verified');
}finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));rmSync(temp,{recursive:true,force:true});}
