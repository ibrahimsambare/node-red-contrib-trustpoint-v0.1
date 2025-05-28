const https = require('https');
const forge = require('node-forge');

module.exports = function (RED) {
    function TrustpointCaCertsNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            const estUrl = config.estUrl || msg.estUrl;
            if (!estUrl) return node.error("EST URL is required (msg.estUrl or config)");

            const url = new URL(estUrl);
            const options = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname.endsWith('/') ? url.pathname + '.well-known/est/cacerts' : url.pathname + '/.well-known/est/cacerts',
                method: 'GET',
                rejectUnauthorized: false // For dev/debug; should be `true` in production
            };

            const req = https.request(options, res => {
                let chunks = [];

                res.on('data', d => chunks.push(d));
                res.on('end', () => {
                    const buffer = Buffer.concat(chunks);

                    try {
                        const certs = forge.asn1.fromDer(buffer.toString('binary'));
                        const bags = forge.pkcs7.messageFromAsn1(certs);
                        const pemCerts = bags.certificates.map(cert => forge.pki.certificateToPem(cert));

                        msg.payload = pemCerts;
                        node.send(msg);
                    } catch (err) {
                        node.error("Failed to parse CA certificates: " + err.message, msg);
                    }
                });
            });

            req.on('error', error => {
                node.error("HTTPS request failed: " + error.message, msg);
            });

            req.end();
        });
    }

    RED.nodes.registerType("trustpoint-cacerts", TrustpointCaCertsNode);
};
