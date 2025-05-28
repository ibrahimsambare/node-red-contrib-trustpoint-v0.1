const forge = require('node-forge');
const fs = require('fs');
const path = require('path');

module.exports = function (RED) {
    function TrustpointKeygenNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            const algorithm = config.algorithm || msg.algorithm || 'RSA';
            const keySize = parseInt(config.keySize || msg.keySize || '2048', 10);
            const curve = config.ecCurve || msg.ecCurve || 'prime256v1';
            const persist = config.persist === true || msg.persist === true;
            const filenamePrefix = config.filenamePrefix || msg.filenamePrefix || 'keypair';

            let privateKeyPem, publicKeyPem;

            try {
                if (algorithm === 'RSA') {
                    const keys = forge.pki.rsa.generateKeyPair(keySize);
                    privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
                    publicKeyPem = forge.pki.publicKeyToPem(keys.publicKey);
                } else if (algorithm === 'EC' || algorithm === 'ECC') {
                    const ec = forge.pki.ec;
                    const keypair = ec.generateKeyPair({namedCurve: curve});
                    privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
                    publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
                } else {
                    return node.error(`Unsupported algorithm: ${algorithm}`);
                }

                if (persist) {
                    const dir = path.join(__dirname, '..', 'keys');
                    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
                    fs.writeFileSync(path.join(dir, `${filenamePrefix}_private.pem`), privateKeyPem);
                    fs.writeFileSync(path.join(dir, `${filenamePrefix}_public.pem`), publicKeyPem);
                }

                msg.payload = {
                    algorithm,
                    privateKey: privateKeyPem,
                    publicKey: publicKeyPem
                };

                node.send(msg);
            } catch (err) {
                node.error(`Key generation failed: ${err.message}`, msg);
            }
        });
    }

    RED.nodes.registerType("trustpoint-keygen", TrustpointKeygenNode);
};
