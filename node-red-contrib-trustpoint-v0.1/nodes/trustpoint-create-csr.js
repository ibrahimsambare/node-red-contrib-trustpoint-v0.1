const forge = require('node-forge');

module.exports = function (RED) {
    function TrustpointCreateCsrNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            try {
                const privateKeyPem = msg.payload.privateKey || config.privateKey;
                if (!privateKeyPem) return node.error("No private key provided in msg.payload.privateKey");

                const subject = msg.payload.subject || {
                    CN: config.cn || 'example.com',
                    O: config.o || '',
                    OU: config.ou || ''
                };

                const sanArray = msg.payload.san || config.san?.split(',').map(s => s.trim()).filter(Boolean) || [];

                const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

                const csr = forge.pki.createCertificationRequest();
                csr.publicKey = forge.pki.setRsaPublicKey(privateKey.n, privateKey.e); // for RSA

                csr.setSubject([
                    { name: 'commonName', value: subject.CN },
                    ...(subject.O ? [{ name: 'organizationName', value: subject.O }] : []),
                    ...(subject.OU ? [{ name: 'organizationalUnitName', value: subject.OU }] : [])
                ]);

                if (sanArray.length > 0) {
                    csr.setAttributes([{
                        name: 'extensionRequest',
                        extensions: [{
                            name: 'subjectAltName',
                            altNames: sanArray.map(value => ({
                                type: /^[0-9.]+$/.test(value) ? 7 : 2, // IP=7, DNS=2
                                value
                            }))
                        }]
                    }]);
                }

                csr.sign(privateKey);

                const pem = forge.pki.certificationRequestToPem(csr);
                msg.payload.csr = pem;
                node.send(msg);

            } catch (err) {
                node.error("CSR generation failed: " + err.message, msg);
            }
        });
    }

    RED.nodes.registerType("trustpoint-create-csr", TrustpointCreateCsrNode);
};
