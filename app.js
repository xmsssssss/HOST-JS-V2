const http = require('http');
const { Buffer } = require('buffer');
const net = require('net');
const { WebSocket, createWebSocketStream } = require('ws');
const DOMAIN = process.env.DOMAIN || '';  //必须填写哈 参数是DOMAIN
const UUID = process.env.UUID || 'b28f60af-d0b9-4ddf-baaa-7e49c93c380b';
const uuid = UUID.replace(/-/g, "");
const NAME = process.env.NAME || 'webhostmost-V2';
const port = process.env.PORT || 3000;

// 创建HTTP路由
const httpServer = http.createServer((req, res) => {
    if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('Hello, World\n');
    } else if (req.url === '/sub') {
        const vlessURL = `vless://${UUID}@${DOMAIN}:443?encryption=none&security=tls&sni=${DOMAIN}&type=ws&host=${DOMAIN}&path=%2F#${NAME}`;

        const base64Content = Buffer.from(vlessURL).toString('base64');

        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(base64Content + '\n');
    } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found\n');
    }
});

httpServer.listen(port, () => {
    console.log(`HTTP Server is running on port ${port}`);
});

// WebSocket 服务器
const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', ws => {
    console.log("WebSocket 连接成功");
    ws.on('message', msg => {
        if (msg.length < 18) {
            console.error("数据长度无效");
            return;
        }
        try {
            const [VERSION] = msg;
            const id = msg.slice(1, 17);
            if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) {
                console.error("UUID 验证失败");
                return;
            }
            let i = msg.slice(17, 18).readUInt8() + 19;
            const port = msg.slice(i, i += 2).readUInt16BE(0);
            const ATYP = msg.slice(i, i += 1).readUInt8();
            const host = ATYP === 1 ? msg.slice(i, i += 4).join('.') :
                (ATYP === 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
                    (ATYP === 3 ? msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
            console.log('连接到:', host, port);
            ws.send(new Uint8Array([VERSION, 0]));
            const duplex = createWebSocketStream(ws);
            net.connect({ host, port }, function () {
                this.write(msg.slice(i));
                duplex.on('error', err => console.error("E1:", err.message)).pipe(this).on('error', err => console.error("E2:", err.message)).pipe(duplex);
            }).on('error', err => console.error("连接错误:", err.message));
        } catch (err) {
            console.error("处理消息时出错:", err.message);
        }
    }).on('error', err => console.error("WebSocket 错误:", err.message));
});
