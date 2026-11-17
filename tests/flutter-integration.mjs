import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import {readFileSync} from 'node:fs';
import {spawn} from 'node:child_process';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import path from 'node:path';

const sdk = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const gateway = process.env.GATEWAY_SOURCE_DIR || '/data/code/gateway';
const {protectPasswordBody}=await import(path.join(gateway,'tools/password-envelope.mjs'));
const origin = process.env.GATEWAY_HOST || 'https://gateway.perfy576.com';
const host = 'gateway-flutter-' + randomBytes(4).toString('hex') + '.invalid';
const appid = 'Flutter_' + randomBytes(4).toString('hex');
const credentialRecord = readFileSync(path.join(gateway, '.secrets/initial-admin.txt'), 'utf8');
const adminUsername = credentialRecord.match(/^Username: (.+)$/m)[1];
const password = credentialRecord.match(/^Password: (.+)$/m)[1];
const target = '/private?from=flutter&next=%2Fdocs';
let adminCookie = '', csrf = '', id = '', secret = '';
const sockets = new Set();
const backend = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify({headers: req.headers, url: req.url}));
});
backend.on('connection', socket => {
  sockets.add(socket); socket.on('error', () => {});
  socket.on('close', () => sockets.delete(socket));
});
await new Promise(resolve => backend.listen(0, '127.0.0.1', resolve));

async function request(route, {method = 'GET', body, admin = false} = {}) {
  const url = new URL(route, origin);
  body=await protectPasswordBody(url.pathname,method,body,async target=>(await request(target,{admin})).json);
  const headers = {Host: url.hostname};
  let data;
  if (admin) headers.Cookie = adminCookie;
  if (body !== undefined) {
    data = JSON.stringify(body);
    headers['Content-Type'] = 'application/json';
    headers['Content-Length'] = Buffer.byteLength(data);
    if (admin) Object.assign(headers, {Origin: origin, 'X-Gateway-Request': '1', 'X-CSRF-Token': csrf});
  }
  return new Promise((resolve, reject) => {
    const req = https.request({hostname: '127.0.0.1', port: 443,
      servername: new URL(origin).hostname, path: url.pathname + url.search,
      method, headers}, res => {
      const chunks = []; res.on('data', c => chunks.push(c));
      res.on('end', () => {
        try { resolve({status: res.statusCode, headers: res.headers, json: JSON.parse(Buffer.concat(chunks))}); }
        catch (error) { reject(error); }
      });
    });
    req.on('error', reject); req.setTimeout(15000, () => req.destroy(new Error('Request timed out')));
    req.end(data);
  });
}
async function api(route, method = 'GET', body) {
  const response = await request(route, {method, body, admin: true});
  assert.equal(response.status, 200, JSON.stringify(response.json));
  return response.json;
}
function run(command, args, input, extraEnv = {}, cwd = sdk) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {cwd, env: {...process.env,
      GATEWAY_TOKEN_SECRET: secret, ...extraEnv}, stdio: ['pipe', 'pipe', 'pipe']});
    let output = '', error = '';
    child.stdout.on('data', data => output += data);
    child.stderr.on('data', data => error += data);
    child.on('error', reject);
    child.on('close', code => {
      try { assert.equal(code, 0, command + ': ' + error); resolve(JSON.parse(output)); }
      catch (failure) { reject(failure); }
    });
    child.stdin.end(JSON.stringify(input));
  });
}
try {
  const auth = await request('/api/login', {method: 'POST', admin: true,
    body: {username: adminUsername, password, mode: 'admin'}});
  assert.equal(auth.status, 200);
  adminCookie = auth.headers['set-cookie'].map(c => c.split(';')[0]).join('; ');
  const me = await api('/api/me');csrf = me.csrf;
  id = (await api('/api/admin/services', 'POST', {appid, host, name: 'Flutter SDK integration',
    upstream: 'http://127.0.0.1:' + backend.address().port,
    enabled: true, allow_all: false, users: [me.user.id], excluded_paths: []})).id;
  secret = (await api(`/api/admin/services/${id}/secret`, 'POST', {})).secret;
  const input = {gateway_host: origin, audience: host, appid, uri: target, method: 'GET'};
  const result = await run('dart', ['run', 'tool/live_probe.dart'], input,
    {GATEWAY_USERNAME: adminUsername, GATEWAY_PASSWORD: password}, path.join(sdk, 'flutter-sdk'));
  assert.equal(result.result, 'Ok'); assert.equal(result.username, adminUsername);
  const sessions=(await api('/api/admin/state')).sessions.filter(session=>session.service_id===id);
  assert(sessions.length>0);
  assert(sessions.every(session=>session.app_package==='com.example.gateway.integration'&&session.user_agent==='GatewayFlutterIntegration/2.0.0'));
  const audits=(await api('/api/admin/audit')).entries.filter(entry=>entry.action==='login.success'&&entry.detail==='appid='+appid);
  assert(audits.length>0);
  assert(audits.every(entry=>entry.app_package==='com.example.gateway.integration'&&entry.user_agent==='GatewayFlutterIntegration/2.0.0'));
  console.log('PASS real Flutter SDK package and User-Agent reach Gateway sessions and audit');
  console.log('PASS Dart/Flutter: ' + result.checks.join(', '));
  for (const language of ['python', 'cpp']) {
    const command = language === 'python' ? path.join(sdk, '.venv/bin/python') : path.join(sdk, 'build/gateway-sdk-verify');
    const args = language === 'python' ? [path.join(sdk, 'python3-sdk/examples/verify.py')] : [];
    const checked = await run(command, args, {...input, operation: 'checkCookie', ...result.forwarded});
    assert.equal(checked.result, 'Ok'); assert.equal(checked.claims.appid, appid);
    console.log('PASS ' + language + ': validates the same Flutter-originated gateway request');
  }
} finally {
  if (id) await api('/api/admin/services/' + id, 'DELETE', {}).catch(error => {
    console.error('Service cleanup failed:', error.message); process.exitCode = 1;
  });
  for (const socket of sockets) socket.destroy();
  await new Promise(resolve => backend.close(resolve));
}
