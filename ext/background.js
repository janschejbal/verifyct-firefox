var db;

var verbose = false;


class WorkerHandler {
  constructor() {
    this.worker = new Worker("worker/worker.js", { type: "module" });
    this.counter = 1;
    this.outstanding = {}
    this.worker.onmessage = (e) => { this.onmessage(e) };
    this.worker.onerror = (e) => { console.log("WorkerHandler error", e); };
    this.worker.onmessageerror = (e) => { console.log("WorkerHandler messageerror", e); };
  }

  onmessage(msg) {
    if (verbose) {
      console.log("WorkerHandler.onmessage", msg, msg.data);
    }
    if (!msg.data) {
      return;
    }
    if ('seq' in msg.data && this.outstanding[msg.data.seq]) {
      if ('result' in msg.data) {
        this.outstanding[msg.data.seq].resolve(msg.data.result);
      }
      if ('error' in msg.data) {
        this.outstanding[msg.data.seq].reject(msg.data.error);
      }
      delete this.outstanding[msg.data.seq];
    }
    if ('log' in msg.data) {
      console.log("Message from worker", ...msg.data.log)
    }
  }

  call(funcName, ...args) {
    if (verbose) {
      console.log("WorkerHandler.call", funcName, args, this.counter);
    }
    const id = this.counter++;
    const p = new Promise((resolve, reject) => {
      this.outstanding[id] = {resolve: resolve, reject: reject};
    });
    this.worker.postMessage({f: funcName, args: args, seq: id});
    return p
  }
}

function storeVerifiedLogs(fingerprint, logs) {
  const tx = db.transaction(["certstore2"], "readwrite");
  const request = tx.objectStore("certstore2").openCursor([fingerprint, 1]); // composite key, 1 indicates leaf
  request.onsuccess = (event) => {
    const cursor = event.target.result;
    if (cursor && cursor.value && cursor.value.fp == fingerprint) {
      // Merge the new logs with the existing logs
      if (cursor.value.logs) {
        logs = [...new Set(cursor.value.logs.concat(logs))];
      }
      cursor.value.logs = logs;
      cursor.update(cursor.value);
    } else {
      console.log("storeVerifiedLogs: item not found", cursor);
    }
  };
}

var unverifiedCount = 0;

function updateBadge() {
  browser.browserAction.setBadgeText({text: unverifiedCount ? "" + unverifiedCount : ""});
}

async function newChain(certs, fingerprints) {
  unverifiedCount++;
  updateBadge();
  const rawCerts = certs.slice(0, 2).map((cert) => new Uint8Array(cert.rawDER));
  let res = null;
  try {
    res = await worker.call("verify", rawCerts[0], rawCerts[1]); // TODO provide a UI for viewing certs, viewing logs, updating logs, keeping logs honest through active querying, and active verification (checking that SCTs are included)
  } catch (e) {
    console.log("verification failed for", fingerprints[0]);
    return;
  }
  storeVerifiedLogs(fingerprints[0], res);
  if (res.length >= 2) { // TODO be more picky about diversity and status of logs
    if (verbose) {
      console.log("good SCTs for", fingerprints[0], res);
    }
    unverifiedCount--;
    updateBadge();
  } else {
    console.log("not enough valid SCTs for", fingerprints[0], res);
  }
}


function insertNew(tx, store, data) {
  const req = tx.objectStore(store).add(data)
  req.onerror = (event) => {
    // Ignore "error" indicating that an entry with this key already exists.
    if (req.error.name == "ConstraintError") {
      event.preventDefault();
      event.stopPropagation();
    } 
  }
  return req
}

function infoListener(requestDetails, securityInfo) {
  //console.log("Got SecurityInfo", requestDetails, securityInfo);
  const tx = db.transaction(["certstore2", "chainstore"], "readwrite");
  if (!securityInfo.certificates || securityInfo.certificates.length == 0) {
    return;
  }
  const fingerprints = securityInfo.certificates.map((cert) => cert.fingerprint.sha256.replaceAll(":",""));

  // TODO keep fingerprints in memory, bail out early? for 5k distinct certs x 3 entries per chain = 5000*3*64 bytes = 1M + overhead, acceptable.

  securityInfo.certificates.forEach((cert, i) => {
    const first_seen = {"origin": new URL(requestDetails.url).origin, "t": requestDetails.timeStamp};  // TODO log validity?
    const is_leaf = i==0 ? 1 : 0;  // bool is unsupported for indices, see https://github.com/w3c/IndexedDB/issues/76
    const certData = {"fp": fingerprints[i], "leaf": is_leaf, "first": first_seen, "der": cert.rawDER};
    const req = insertNew(tx, "certstore2", certData)
    req.onsuccess = (event) => {
      if (verbose) {
        console.log("new cert", certData, cert);
      }
    }
  });

  const chainData = {"leaf": fingerprints[0], "rest": fingerprints.slice(1)};
  const req = insertNew(tx, "chainstore", chainData);
  req.onsuccess = (event) => {
    // new chain discovered
    tx.oncomplete = (event) => {
      // call newChain *after* the transaction is compelete
      newChain(securityInfo.certificates, fingerprints);
    }
    if (verbose) {
      console.log("new chain", chainData);
    }
  }
}

function connectionListener(requestDetails) {
  browser.webRequest.getSecurityInfo(
      requestDetails.requestId,
      {certificateChain: true, rawDER: true},
  ).then((si) => infoListener(requestDetails, si));
}

function startConnectionListener(db_) {
  db = db_;
  db.onerror = (event) => {
    console.error(`Database error`, event);
  };
  // According to https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/getSecurityInfo,
  // getSecurityInfo can only be used inside onHeadersReceived, and ["blocking"] must be set.
  // At this point, cookies etc. have already been sent. We could still block the request to prevent e.g. malicious injected JavaScript from being served, but the complexity and performance impact are likely not worth it.
  // Thus, even though "blocking" is set, we don't actually block.
  browser.webRequest.onHeadersReceived.addListener(
      connectionListener,
      {urls: ["<all_urls>"]},
      ["blocking"]
  );
  console.log("listener added");
}

function initDB() {
  const request = indexedDB.open("VerifyCT_DB", 2);
  request.onerror = (event) => {
    console.error("Could not open DB", event);
  };
  request.onsuccess = (event) => {
    console.log("db open");
    const db_ = event.target.result;
    startConnectionListener(db_);
  } 
  request.onupgradeneeded = (event) => {
    console.log("db upgrade");
    const db_ = event.target.result;
    if (!db_.objectStoreNames.contains("certstore2")) {
      const certstore = db_.createObjectStore("certstore2", { keyPath: ["fp", "leaf"]});
    }
    if (!db_.objectStoreNames.contains("chainstore")) {
      const chainstore = db_.createObjectStore("chainstore", { keyPath: ["leaf", "rest"]});
      chainstore.createIndex("leafIndex", "leaf", { unique: false });
    }
  };
}

function handleClick() {
  browser.browserAction.openPopup();
}

async function loadLogList() {
  const loglist = (await browser.storage.local.get("loglist")).loglist;
  if (loglist) {
    await worker.call("updateLogs", loglist);
    console.log("Log list pushed to worker", loglist);
  }
}

browser.browserAction.onClicked.addListener(handleClick);
browser.runtime.onMessage.addListener((data, sender) => {
  console.log("browser.runtime.onMessage", data, sender);
  if (!sender.url.startsWith(browser.extension.getURL(""))) {
    console.log("ignoring untrusted message");
    return false;
  }
  if (data.f === "refreshLogList") {
    return loadLogList();
  }
  if (data.f === "resetCount") {
    unverifiedCount = 0;
    updateBadge();
    return Promise.resolve(true);
  }
  return false;
});


const worker = new WorkerHandler();
loadLogList();
initDB();
