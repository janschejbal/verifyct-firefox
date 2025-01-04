
// Helper function: Read all entries from the given store using the given tx.
// This is a workaround for getAll failing with "The operation failed for reasons unrelated to the database itself and not covered by any other error code." as of Firefox 133 if the DB is too big.
// The returned array will be populated *after* this function has returned! Wait for tx.oncomplete before reading it.
function readStoreAsync(tx, storename) {
  const curReq = tx.objectStore(storename).openCursor();
  const result = []
  curReq.onsuccess = (e) => {
    const cur = curReq.result;
    if (cur) {
      result.push(cur.value);
      cur.continue();
    }
  }
  return result;
}

function download() {
  const page = browser.extension.getBackgroundPage();
  const tx = page.db.transaction(["certstore2", "chainstore"], "readonly");
  const certs = readStoreAsync(tx, "certstore2");
  const chains = readStoreAsync(tx, "chainstore");
  tx.oncomplete = (event) => {
    certs.forEach((c) => {
      c.der = btoa(String.fromCharCode(...c.der));
    })
    out = JSON.stringify({
      certs: certs,
      chains: chains
    });
    const url = URL.createObjectURL(new Blob([out]));
    var a = document.createElement("a");
    document.body.appendChild(a);
    a.style.display = "none";
    a.href = url;
    a.download = "VerifyCT_dump.json";
    a.click();
    window.URL.revokeObjectURL(url);
  };
}

function getCount() {
  return new Promise((resolve) => {
    const page = browser.extension.getBackgroundPage();
    const tx = page.db.transaction(["certstore2", "chainstore"], "readonly");
    const req1 = tx.objectStore("certstore2").count();
    const req2 = tx.objectStore("chainstore").count();
    tx.oncomplete = () => {
      resolve([req1.result, req2.result]);
    };
  });
}


async function fetchLogList() {
  const fetchList = fetch('https://www.gstatic.com/ct/log_list/v3/log_list.json');
  const fetchSig = fetch('https://www.gstatic.com/ct/log_list/v3/log_list.sig');
  const fetchKey = fetch('data/loglist_signing_key.rsa.pub');
  const key = await crypto.subtle.importKey(
      "spki",
      await (await fetchKey).arrayBuffer(),
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      true,
      ["verify"],
  );
  
  const loglist = await (await fetchList).arrayBuffer()
  const sig = await (await fetchSig).arrayBuffer()
  if (!await crypto.subtle.verify(key.algorithm, key, sig, loglist)) {
    throw "CT log list signature verification failed";
  }
  return new TextDecoder().decode(loglist);
}

async function updateLogList() {
  try {
    const listText = await fetchLogList();
    await browser.storage.local.set({"loglist": listText});
    browser.runtime.sendMessage({f: "refreshLogList"});
  } catch (e) {
    alert("Failed to update log list: " + e);
    console.log("Failed to update logs", e);
  }
}

function resetCount() {
  browser.runtime.sendMessage({f: "resetCount"});
}

window.onload = () => {
  document.getElementById("logupdatebutton").addEventListener("click", updateLogList);
  document.getElementById("downloadbutton").addEventListener("click", download);
  getCount().then((n) => {
    document.getElementById("statustext").innerText = `${n[0]} certs, ${n[1]} chains seen (new storage)`;
  });
  document.getElementById("resetbutton").addEventListener("click", resetCount);
}
