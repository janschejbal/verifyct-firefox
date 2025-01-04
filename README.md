# VerifyCT for Firefox

This is an **experimental, work in progress** extension trying to bring [Certificate Transparency](https://certificate.transparency.dev/) support to Firefox.

At the current stage, you should **not** use this extension unless you are familiar with Certificate Transparency (i.e. you know what an SCT is), and willing to deal with issues and look at the console for output.

The extension is available at https://addons.mozilla.org/en-US/firefox/addon/verifyct/

## Permissions
The extension needs to use [getSecurityInfo](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/getSecurityInfo) to get access to the certificates. As the documentation explains, this unfortunately requires `webRequest`, `webRequestBlocking` and host permissions for all hosts where we want to monitor certificates (i.e. `<all_urls>`).

`storage` and `unlimitedStorage` are used to store e.g. the CT log list and certificate data.


## Supply chain security
The JavaScript/npm ecosystem is known for its sprawling dependency trees and resulting supply chain attacks. I've tried to minimize dependencies and apply some hardening.

### What's included
See [package.json](node/package.json) and [package-lock.json](node/package-lock.json) for all dependencies.

The well-known [PKI.js](https://github.com/PeculiarVentures/PKI.js) (from @PeculiarVentures) is basically unavoidable when working with certificates. [CTjs](https://github.com/YuryStrozhevsky/CTjs) (from @YuryStrozhevsky, one of the PKI.js contributors) provides code for handling Certificate Transparency. These are luckily relatively light on  dependencies and the dependencies are from the same authors, limiting exposure.

I'm bundling all dependencies into [deps.js](node/dist/deps.js) and also exposing the transitive dependencies there, and checking this file into git. This makes it possible to develop the extension without having to use a build system.

For bundling, [rollup.js](https://rollupjs.org/) and its transitive dependencies are used.

### Reproducible builds

The build can be run sandboxed in a docker container:

```
$ sudo docker pull node:alpine
$ sudo docker image ls node --digests
REPOSITORY   TAG       DIGEST                                                                    IMAGE ID       CREATED      SIZE
node         alpine    sha256:181d0e0248e825fa1c056c7ef85e91fbad340caf0814d30b81467daea4637045   52a11a0f9868   4 days ago   148MB
$ sudo docker run -u 1000 -it --rm -w /work -v "$PWD/node":/work node:alpine npm install
$ sudo docker run -u 1000 -it --rm -w /work -v "$PWD/node":/work node:alpine npm run build
```

I will likely *not* update the digest above each time I rebuild. However, the build output appeared stable even when I tried with an older node container. 

### Hardening

I am unable to fully review the dependencies. As an additional precaution, I'm only including the dependencies in a WebWorker running in the background. This worker should not have direct access to the extension APIs. While I'm not 100% confident that this is a solid security boundary, it should limit the risk of exposure at least against untargeted supply chain attacks.

### Key provenance

ext/data/loglist_signing_key.rsa.pub is https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem converted to binary (DER) format: `openssl rsa -pubin -inform pem -outform der`
