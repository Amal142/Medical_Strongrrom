const usbDecode = s => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
const usbEncode = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');

async function deriveFileKey(passphrase, salt, iterations) {
  const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2',salt,iterations,hash:'SHA-256'}, material,
    {name:'AES-GCM',length:256}, false, ['encrypt']
  );
}

async function enrollUsbKey(options, challengeId, endpoint, username, passphrase, confirmation) {
  if (!passphrase || passphrase.length < 12) throw new Error('Use a key-file passphrase of at least 12 characters.');
  if (passphrase !== confirmation) throw new Error('The passphrases did not match.');
  // Start the save picker inside the user click before any asynchronous prompts.
  const safeUsername = username.trim().replace(/[^a-z0-9._-]/gi,'_').replace(/^[_\.]+|[_\.]+$/g,'') || 'user';
  const filename = `${safeUsername}.strongroom-key`;
  const filePicker = window.showSaveFilePicker
    ? window.showSaveFilePicker({suggestedName:filename,types:[{description:'Encrypted Medical Strongroom key file',accept:{'application/json':['.strongroom-key']}}]})
    : null;
  const pair = await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
  const privateDer = await crypto.subtle.exportKey('pkcs8',pair.privateKey);
  const publicDer = await crypto.subtle.exportKey('spki',pair.publicKey);
  const credentialIdBytes = crypto.getRandomValues(new Uint8Array(32));
  const credentialId = usbEncode(credentialIdBytes.buffer);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const iterations = 310000;
  const aesKey = await deriveFileKey(passphrase,salt,iterations);
  const encryptedPrivateKey = await crypto.subtle.encrypt({name:'AES-GCM',iv},aesKey,privateDer);
  const keyFile = JSON.stringify({
    format:'medical-strongroom-usb-key-v2',username,credential_id:credentialId,
    encryption:{algorithm:'AES-256-GCM',kdf:'PBKDF2-SHA-256',iterations,salt:usbEncode(salt),iv:usbEncode(iv)},
    encrypted_private_key:usbEncode(encryptedPrivateKey)
  },null,2);

  if (filePicker) {
    const handle = await filePicker;
    const writable = await handle.createWritable();
    await writable.write(new Blob([keyFile],{type:'application/json'}));
    await writable.close();
  } else {
    const link=document.createElement('a'); link.href=URL.createObjectURL(new Blob([keyFile],{type:'application/json'}));
    link.download=filename; link.click(); setTimeout(()=>URL.revokeObjectURL(link.href),60000);
    if(!window.confirm(`Save ${filename} onto your USB drive, then choose OK to continue.`)) throw new Error('Save the key file to USB before continuing.');
  }

  const signature = await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},pair.privateKey,usbDecode(options.challenge));
  const csrfCookie = document.cookie.split('; ').find(value => value.startsWith('strongroom_csrf='));
  const csrfToken = csrfCookie ? decodeURIComponent(csrfCookie.slice('strongroom_csrf='.length)) : '';
  const response = await fetch(endpoint,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken},body:JSON.stringify({challenge_id:challengeId,credential_id:credentialId,public_key:usbEncode(publicDer),signature:usbEncode(signature)})});
  const result=await response.json();
  if(!response.ok) throw new Error(result.error||'The server rejected the new key.');
  return result;
}
