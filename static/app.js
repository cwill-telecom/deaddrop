/**
 * DeadDrop — client-side AES-256-GCM file encryption.
 *
 * All crypto happens in the browser via the Web Crypto API.
 * The server never sees plaintext file contents or original filenames.
 *
 * Upload flow:
 *   1. User picks file + provides password
 *   2. PBKDF2 derives a 256-bit key (salt + 250K iterations + SHA-256)
 *   3. File content + original filename encrypted with AES-256-GCM
 *   4. Salt + IVs + ciphertexts packed into a single blob
 *   5. Blob uploaded under a random name → /storage/file_NNN.dat
 *
 * Download flow:
 *   1. User clicks download, enters password
 *   2. Blob fetched from server
 *   3. Salt extracted, key re-derived
 *   4. Filename + file content decrypted with AES-256-GCM
 *   5. Original file saved to disk
 *   6. Server sent /delete — zero-fills then unlinks the encrypted blob
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/* Crypto primitives  */

async function deriveKey(password, salt) {
  const base = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encrypt(key, data) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, data);
  return { iv, ct };
}

async function decrypt(key, iv, ct) {
  return crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
}

function pack(salt, nameIv, nameCt, fileIv, fileCt) {
  const total = salt.length + nameIv.length + nameCt.byteLength + 1 +
                fileIv.length + fileCt.byteLength;
  const buf = new Uint8Array(total);
  let off = 0;
  buf.set(salt, off); off += salt.length;
  buf.set(nameIv, off); off += nameIv.length;
  buf.set(new Uint8Array(nameCt), off); off += nameCt.byteLength;
  buf[off++] = 0;  // delimiter
  buf.set(fileIv, off); off += fileIv.length;
  buf.set(new Uint8Array(fileCt), off);
  return buf;
}

/*  DOM refs */

const fileInput   = document.getElementById("fileInput");
const uploadZone  = document.getElementById("uploadZone");
const zoneLabel   = document.getElementById("zoneLabel");
const zoneIcon    = document.getElementById("zoneIcon");
const keyInput    = document.getElementById("keyInput");
const uploadBtn   = document.getElementById("uploadBtn");
const fileList    = document.getElementById("fileList");
const fileCount   = document.getElementById("fileCount");
const statusText  = document.getElementById("statusText");
const toastEl     = document.getElementById("toast");

/*  Helpers  */

function toast(msg, isErr) {
  toastEl.textContent = msg;
  toastEl.className = "toast show" + (isErr ? " error" : "");
  setTimeout(() => toastEl.className = "toast", 2500);
}

function fmtSize(bytes) {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

function updateFileCount() {
  const n = fileList.querySelectorAll(".file-row").length;
  fileCount.textContent = n === 0 ? "no files" : n + " file" + (n !== 1 ? "s" : "");
}

/*  Drag & drop */

uploadZone.addEventListener("dragover", e => {
  e.preventDefault();
  uploadZone.classList.add("dragover");
});
uploadZone.addEventListener("dragleave", () => {
  uploadZone.classList.remove("dragover");
});
uploadZone.addEventListener("drop", e => {
  e.preventDefault();
  uploadZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    showPickedFile(e.dataTransfer.files[0]);
  }
});

uploadZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  if (fileInput.files.length) showPickedFile(fileInput.files[0]);
});

function showPickedFile(file) {
  zoneIcon.textContent = "📦";
  zoneLabel.innerHTML = `<span class="filename">${file.name}</span>`;
  const hint = uploadZone.querySelector(".hint");
  if (hint) hint.textContent = fmtSize(file.size);
}

/* Upload*/

uploadBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  const pass = keyInput.value.trim();
  if (!file) return toast("Select a file first", true);
  if (!pass)  return toast("Enter an encryption key", true);

  uploadBtn.disabled = true;
  uploadBtn.innerHTML = '<span class="spinner"></span> Encrypting...';
  statusText.textContent = "encrypting...";

  try {
    const salt    = crypto.getRandomValues(new Uint8Array(16));
    const key     = await deriveKey(pass, salt);
    const fileBuf = new Uint8Array(await file.arrayBuffer());
    const nameBuf = encoder.encode(file.name);

    const { iv: nIv, ct: nCt } = await encrypt(key, nameBuf);
    const { iv: fIv, ct: fCt } = await encrypt(key, fileBuf);

    const packed   = pack(salt, nIv, nCt, fIv, fCt);
    const blob     = new Blob([packed]);
    const formData = new FormData();
    const randName = "file_" + Date.now() + ".dat";
    formData.append("file", blob, randName);

    statusText.textContent = "uploading...";
    const res = await fetch("/", { method: "POST", body: formData });

    if (!res.ok) throw new Error("Upload failed (" + res.status + ")");

    toast("Uploaded — encrypted end-to-end");
    keyInput.value = "";
    zoneIcon.textContent = "📁";
    zoneLabel.innerHTML = '<span class="hint">Click or drag a file here</span>';
    fileInput.value = "";
    window.location.reload();
  } catch (err) {
    toast(err.message, true);
    console.error(err);
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.innerHTML = "⬆ Upload";
    statusText.textContent = "idle";
  }
});

/* Download  */

fileList.addEventListener("click", async e => {
  const btn = e.target.closest(".download-btn");
  if (!btn) return;
  const filename = btn.dataset.file;
  const pass = prompt("Enter decryption key for this file");
  if (!pass) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';
  statusText.textContent = "downloading...";

  try {
    const res = await fetch("/download/" + encodeURIComponent(filename));
    if (!res.ok) throw new Error("Download failed (" + res.status + ")");

    const data   = new Uint8Array(await res.arrayBuffer());
    let off      = 0;
    const salt   = data.slice(off, off + 16); off += 16;
    const key    = await deriveKey(pass, salt);
    const nIv    = data.slice(off, off + 12); off += 12;
    const nEnd   = data.indexOf(0, off);
    const nCt    = data.slice(off, nEnd);
    off          = nEnd + 1;
    const fIv    = data.slice(off, off + 12); off += 12;
    const fCt    = data.slice(off);

    statusText.textContent = "decrypting...";
    const nameBuf = await decrypt(key, nIv, nCt);
    const fileBuf = await decrypt(key, fIv, fCt);
    const origName = decoder.decode(nameBuf);

    const blob = new Blob([fileBuf]);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = origName;
    a.click();
    URL.revokeObjectURL(url);

    statusText.textContent = "wiping...";
    const delRes = await fetch("/delete/" + encodeURIComponent(filename), { method: "POST" });
    if (delRes.ok) {
      btn.closest(".file-row").remove();
      updateFileCount();
      toast("Downloaded — file wiped from server");
    } else {
      toast("Downloaded but server delete failed", true);
    }
  } catch (err) {
    toast("Decryption failed — wrong key?", true);
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "⬇ Download";
    statusText.textContent = "idle";
  }
});

/* Init */

updateFileCount();
