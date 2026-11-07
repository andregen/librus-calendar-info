'use strict';
const $ = id => document.getElementById(id);
const bytes64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const from64 = value => Uint8Array.from(atob(value), c => c.charCodeAt(0));
let key, keyid;
async function init() {
  const r = await fetch('setup-public.pem', {cache:'no-store'});
  if (!r.ok) throw new Error('key');
  const pem = await r.text();
  const der = from64(pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, ''));
  key = await crypto.subtle.importKey('spki', der, {name:'RSA-OAEP',hash:'SHA-256'}, false, ['encrypt']);
  keyid = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', der)), b => b.toString(16).padStart(2,'0')).join('');
  $('keyid').textContent = 'Отпечаток ключа: ' + keyid;
}
const ready = init().catch(() => { $('status').textContent = 'Не удалось загрузить ключ. Ничего не отправлено.'; $('encrypt').disabled = true; });
$('encrypt').onclick = async () => {
  await ready;
  if (!key || !$('token').value.trim()) { $('status').textContent = 'Введите токен бота.'; return; }
  try {
    const data = new TextEncoder().encode(JSON.stringify({token:$('token').value.trim()}));
    const aes = await crypto.subtle.generateKey({name:'AES-GCM',length:256}, true, ['encrypt']);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt({name:'AES-GCM',iv}, aes, data);
    const wrapped = await crypto.subtle.encrypt({name:'RSA-OAEP'}, key, await crypto.subtle.exportKey('raw', aes));
    const packet = {v:1,keyid,key:bytes64(wrapped),iv:bytes64(iv),data:bytes64(encrypted)};
    $('output').value = 'FAMILY1.' + bytes64(new TextEncoder().encode(JSON.stringify(packet)));
    $('token').value = ''; data.fill(0);
    $('result').hidden = false; $('status').textContent = 'Зашифровано на телефоне. Скопируйте пакет в чат.';
  } catch { $('status').textContent = 'Шифрование не удалось. Ничего не отправлено.'; }
};
$('copy').onclick = async () => {
  try { await navigator.clipboard.writeText($('output').value); $('status').textContent = 'Пакет скопирован.'; }
  catch { $('output').select(); $('status').textContent = 'Выделен пакет — скопируйте его вручную.'; }
};
