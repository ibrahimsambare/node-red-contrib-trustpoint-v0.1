const fs = require('fs');
const path = require('path');

module.exports = function (RED) {
    function TrustpointStoreNode(config) {
        RED.nodes.createNode(this, config);
        const node = this;

        node.on('input', function (msg) {
            const operation = config.operation || msg.operation || 'store';
            const location = config.location || msg.location || 'file';
            const format = config.format || msg.format || 'pem';
            const key = config.key || msg.key || 'default-key';
            const filePath = config.filePath || msg.filePath;
            const content = msg.payload;

            if (!content && operation === 'store') {
                return node.error("No content provided in msg.payload");
            }

            try {
                if (location === 'file') {
                    if (!filePath) return node.error("No filePath provided for file storage");

                    if (operation === 'store') {
                        const dir = path.dirname(filePath);
                        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
                        fs.writeFileSync(filePath, content);
                        node.log(`Stored content to ${filePath}`);
                        msg.payload = { status: 'stored', path: filePath };
                    } else if (operation === 'retrieve') {
                        if (!fs.existsSync(filePath)) return node.error(`File not found: ${filePath}`);
                        const fileContent = fs.readFileSync(filePath, 'utf-8');
                        msg.payload = fileContent;
                        node.log(`Retrieved content from ${filePath}`);
                    } else {
                        return node.error("Unsupported operation");
                    }

                } else if (location === 'context') {
                    const target = config.contextScope || 'flow';
                    const context = (target === 'flow') ? node.context().flow : node.context().global;

                    if (operation === 'store') {
                        context.set(key, content);
                        msg.payload = { status: 'stored', scope: target, key };
                    } else if (operation === 'retrieve') {
                        const stored = context.get(key);
                        if (!stored) return node.error(`Key not found in ${target} context`);
                        msg.payload = stored;
                    } else {
                        return node.error("Unsupported operation");
                    }

                } else {
                    return node.error("Invalid storage location");
                }

                node.send(msg);
            } catch (err) {
                node.error(`trustpoint-store error: ${err.message}`, msg);
            }
        });
    }

    RED.nodes.registerType("trustpoint-store", TrustpointStoreNode);
};
