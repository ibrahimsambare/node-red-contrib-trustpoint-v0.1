const https = require('https');
const forge = require('node-forge');
const fs = require('fs');

module.exports = function (RED) {
    function TrustpointSimpleReenrollNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            const estHost = config.estHost || msg.estHost;
            const clientCertPem = msg.payload.cert || config.cert;
            const clientKeyPem = msg.payload.key || config.key;

            if (!estHost || !clientCertPem || !clientKeyPem) {
                return node.error("Missing estHost, cert, or key in msg.payload");
            }

            try {
                const cert = forge.pki.certificateFromPem(clientCertPem);
                const key = forge.pki.privateKeyFromPem(clientKeyPem);
                const csr = forge.pki.createCertificationRequest();

                csr.publicKey = cert.publicKey;
                csr.setSubject(cert.subject.attributes);
                csr.sign(key);

                const csrDer = Buffer.from(forge.asn1.toDer(forge.pki.certificationRequestToAsn1(csr)).getBytes(), 'binary');

                const options = {
                    hostname: estHost,
                    port: 443,
                    path: '/.well-known/est/simplereenroll',
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/pkcs10',
                        'Content-Length': csrDer.length
                    },
                    key: clientKeyPem,
                    cert: clientCertPem,
                    rejectUnauthorized: false
                };

                const req = https.request(options, res => {
                    let chunks = [];

                    res.on('data', chunk => chunks.push(chunk));
                    res.on('end', () => {
                        const buffer = Buffer.concat(chunks);
                        if (res.statusCode === 200) {
                            try {
                                const renewedCert = forge.pki.certificateToPem(
                                    forge.pki.certificateFromAsn1(
                                        forge.asn1.fromDer(buffer.toString('binary'))
                                    )
                                );
                                msg.payload = renewedCert;
                                node.send(msg);
                            } catch (e) {
                                node.error("Failed to parse renewed certificate: " + e.message, msg);
                            }
                        } else {
                            node.error(`Re-enrollment failed (HTTP ${res.statusCode})`, msg);
                        }
                    });
                });

                req.on('error', err => {
                    node.error("HTTPS error: " + err.message, msg);
                });

                req.write(csrDer);
                req.end();

            } catch (e) {
                node.error("Reenrollment error: " + e.message, msg);
            }
        });
    }

    RED.nodes.registerType("trustpoint-simplereenroll", TrustpointSimpleReenrollNode);
};
