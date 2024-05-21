function downloadOld() {
  const page = browser.extension.getBackgroundPage();
  const transaction = page.db.transaction(["certstore"], "readonly");
  const certstore = transaction.objectStore("certstore");
  const req = certstore.getAll();
  req.onsuccess = (event) => {
    const out = [];
    req.result.forEach((certData) => {
      out.push(btoa(String.fromCharCode(...certData.der)));
      out.push("\n");
    });
    const url = URL.createObjectURL(new Blob(out));
    var a = document.createElement("a");
    document.body.appendChild(a);
    a.style.display = "none";
    a.href = url;
    a.download = "VerifyCT_dump.txt";
    a.click();
    window.URL.revokeObjectURL(url);
  };
}

function getCountOld() {
  return new Promise((resolve) => {
    const page = browser.extension.getBackgroundPage();
    const transaction = page.db.transaction(["certstore"], "readonly");
    const certstore = transaction.objectStore("certstore");
    const req = certstore.count();
    req.onsuccess = () => {
      resolve(req.result);
    };
  });
}

function downloadNew() {
  const page = browser.extension.getBackgroundPage();
  const tx = page.db.transaction(["certstore2", "chainstore"], "readonly");
  const req_certs = tx.objectStore("certstore2").getAll();
  const req_chains = tx.objectStore("chainstore").getAll();
  tx.oncomplete = (event) => {
    certs = req_certs.result;
    certs.forEach((c) => {
      c.der = btoa(String.fromCharCode(...c.der));
    })
    out = JSON.stringify({
      certs: req_certs.result,
      chains: req_chains.result
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

function getCountNew() {
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
  document.getElementById("downloadbutton").addEventListener("click", downloadOld);
  getCountOld().then((n) => {
    document.getElementById("statustext").innerText = "" + n + " certificates seen (old storage)";
  });

  document.getElementById("logupdatebutton").addEventListener("click", updateLogList);
  document.getElementById("download2button").addEventListener("click", downloadNew);
  getCountNew().then((n) => {
    document.getElementById("statustext2").innerText = `${n[0]} certs, ${n[1]} chains seen (new storage)`;
  });
  document.getElementById("resetbutton").addEventListener("click", resetCount);
}