const https = require('https');
const fs = require('fs');
const path = require('path');
const forge = require('node-forge');

module.exports = function (RED) {
    function TrustpointSimpleEnrollNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            const estHost = config.estHost || msg.estHost;
            const csrDer = msg.payload; // should be a Buffer
            const useMtls = config.useMtls || msg.useMtls;
            const useBasic = config.useBasic || msg.useBasic;

            const certPath = config.clientCert || msg.clientCert;
            const keyPath = config.clientKey || msg.clientKey;
            const username = config.username || msg.username;
            const password = config.password || msg.password;

            if (!estHost || !csrDer) {
                return node.error("Missing estHost or CSR buffer in msg.payload");
            }

            const options = {
                hostname: estHost,
                port: 443,
                path: '/.well-known/est/simpleenroll/',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/pkcs10',
                    'Content-Length': csrDer.length
                },
                rejectUnauthorized: false
            };

            if (useBasic && username && password) {
                const auth = Buffer.from(`${username}:${password}`).toString('base64');
                options.headers['Authorization'] = `Basic ${auth}`;
            }

            if (useMtls && certPath && keyPath) {
                try {
                    options.key = fs.readFileSync(keyPath);
                    options.cert = fs.readFileSync(certPath);
                } catch (e) {
                    return node.error("Failed to load client cert or key for mTLS");
                }
            }

            const req = https.request(options, res => {
                let chunks = [];
                res.on('data', d => chunks.push(d));
                res.on('end', () => {
                    const buffer = Buffer.concat(chunks);
                    if (res.statusCode === 200) {
                        try {
                            const certPem = forge.pki.certificateToPem(forge.pki.certificateFromAsn1(forge.asn1.fromDer(buffer.toString('binary'))));
                            msg.payload = certPem;
                            node.send(msg);
                        } catch (err) {
                            node.error("Failed to parse signed certificate: " + err.message, msg);
                        }
                    } else {
                        node.error(`Enrollment failed (HTTP ${res.statusCode})`, msg);
                    }
                });
            });

            req.on('error', err => {
                node.error(`HTTPS error: ${err.message}`, msg);
            });

            req.write(csrDer);
            req.end();
        });
    }

    RED.nodes.registerType("trustpoint-simpleenroll", TrustpointSimpleEnrollNode);
};
