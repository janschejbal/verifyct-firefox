import {pkijs, ctjs, bytestreamjs, asn1js, pvutils, pvtsutils} from './deps.js';

async function forEachAsync(list, f) {
  return Promise.all(list.map(f))
}

class FixedDigitallySigned extends ctjs.DigitallySigned {
  constructor(parameters = {}) {
    super(parameters);
  }

  async verify(data, publicKey) {
    return pkijs.getEngine().crypto.verifyWithPublicKey( // the original code was calling .subtle. which no longer seems to exist
      data,
      new asn1js.OctetString({ valueHex: this.signature.toBER(false) }), // the original code had a hack here that broke
      publicKey,
      { algorithmId: "" },
      "SHA-256"
    );
  }
}

function ctjsSCTFromTimestamp(timestamp) {
  return new ctjs.SignedCertificateTimestamp({
    version: timestamp.version,
    logID: timestamp.logID,
    timestamp: timestamp.timestamp,
    extensions: timestamp.extensions,
    signature: new FixedDigitallySigned(timestamp)  // this extracts the signature, signatureAlgorithm, and hashAlgorithm fields. We use a fixed shim because the ctjs code seems broken.
  });
}


async function verifySCTs(leaf, issuer, scts) {
  const precert = await ctjs.PreCert.fromCertificateAndIssuer({
    certificate: leaf, // warning - will modify cert.extensions in-place to remove poison etc.
    issuer: issuer
  });
  const valid = [];
  await forEachAsync(scts, (async (sct, scti) => {
    const logID = pvtsutils.Convert.ToString(sct.logID, 'base64');
    const log = loadedLogs[logID];
    if (log && await sct.verify(precert.buffer, log.ctjs.key, 1 /*log entry type = precert */)) {
      //workerLog(`verified sct ${scti} from log "${log.loglistEntry.description}", ${logID}`);
      valid.push(logID);
    } else {
      //workerLog(`failed verification for sct ${scti} from log "${log.loglistEntry.description}, ${logID}"`);
    }
  }));
  return valid;
}

async function verify(leaf, issuer) {
  if (!loadedLogs) {
    throw "Logs not loaded";
  }
  if (!leaf) {
    throw "no leaf provided"
  }
  if (!issuer) {
    throw "no issuer provided"
  }
  //workerLog("leaf", leaf, "issuer", issuer)
  const leafCert = pkijs.Certificate.fromBER(leaf);
  const issuerCert = pkijs.Certificate.fromBER(issuer);
  let scts = [];
  leafCert.extensions.forEach((e) => {
    if (e.extnID == pkijs.id_SignedCertificateTimestampList) {
      scts = e.parsedValue.timestamps.map(ctjsSCTFromTimestamp);
    }
  });
  return verifySCTs(leafCert, issuerCert, scts);
}

var loadedLogs = null;

async function updateLogs(loglist) {
  const logData = JSON.parse(loglist);

  const logs = {};
  await forEachAsync(logData.operators, async (operator, operatorIndex) => {
    await forEachAsync(operator.logs, async (log, logIndex) => {
      const key_hash = await crypto.subtle.digest("SHA-256", pvtsutils.Convert.FromBase64(log.key));
      const calculated_log_id = pvtsutils.Convert.ToBase64(key_hash);
      if (calculated_log_id !== log.log_id) {
        throw "Invalid CT log list: log_id/key mismatch";
      }
      const ctjsLog = new ctjs.LogV1({
        "log_id": log.log_id,
        "key": log.key,
        "url": log.url,
        "maximum_merge_delay": log.mmd,
      });
      logs[log.log_id] = {
        "ctjs": ctjsLog,
        "loglistEntry": log,
        "loglistEntryIndex": logIndex,
        "loglistOperator": operator,
        "loglistOperatorIndex": operatorIndex
      };
    });
  });
  loadedLogs = logs;
}

const messageHandlers = {
  "updateLogs": updateLogs,
  "verify": verify
}

self.onmessage = async (e) => {
  //workerLog("worker received", e.data);
  try {
    let res = await messageHandlers[e.data.f].apply(null, e.data.args);
    self.postMessage({seq: e.data.seq, result: res})
  } catch (err) {
    self.postMessage({seq: e.data.seq, error: ""+err})
  }
};

function workerLog(...msg) {
  self.postMessage({log: msg});
}
workerLog("worker init");
