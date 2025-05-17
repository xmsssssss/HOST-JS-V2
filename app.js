const http = require('http');
const net = require('net');
const { WebSocket, createWebSocketStream } = require('ws');
const { parse: uuidParse, stringify: uuidStringify } = require('uuid');
const { Buffer } = require('buffer'); // Explicitly for Buffer.from

// --- Server Configuration ---
// 从环境变量读取或使用默认值
const ENV_PORT = process.env.PORT;
const PORT = ENV_PORT && !isNaN(parseInt(ENV_PORT)) ? parseInt(ENV_PORT) : 65530;

// 你的 VLESS UUID (至少一个)
const ALLOWED_UUIDS_STR = process.env.UUID || '67ba4652-ed81-4b07-9116-11950a84b602'; // 允许多个UUID，用逗号分隔
const ALLOWED_UUIDS = ALLOWED_UUIDS_STR.split(',').map(s => s.trim()).filter(s => s.length > 0);

if (ALLOWED_UUIDS.length === 0 || ALLOWED_UUIDS[0] === 'YOUR_PRIMARY_UUID_HERE') {
    console.error("错误: UUID 未配置或仍为默认值。请设置 UUID 环境变量或在代码中修改 ALLOWED_UUIDS_STR。");
    // 为了方便快速测试，可以生成一个临时UUID
    const tempUuid = uuidStringify(require('crypto').randomBytes(16));
    ALLOWED_UUIDS[0] = tempUuid;
    console.warn(`警告: 使用临时生成的UUID: ${tempUuid}。请务必配置您自己的UUID！`);
    // process.exit(1); // 正式部署时应取消此注释，强制配置UUID
}

const parsedAllowedUuids = ALLOWED_UUIDS.map(u => {
    try {
        return Buffer.from(uuidParse(u));
    } catch (e) {
        console.error(`错误: 无效的UUID格式 "${u}". 请确保它是标准的UUID (例如: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).`);
        process.exit(1);
    }
});

// WebSocket 路径 (客户端连接时需要)
const VLESS_PATH = process.env.VLESS_PATH || '/whm'; // 例如 /ray, /vlessws etc.

// 服务器的公开访问域名 (用于生成订阅链接，!!!必须正确配置!!!)
const SERVER_PUBLIC_DOMAIN = process.env.DOMAIN || 'v2.whm.xms.su'; // 例如 my-vless-server.onrender.com

// 订阅链接中每个配置的备注前缀
const SERVER_REMARKS_PREFIX = process.env.REMARKS_PREFIX || 'MyVLESS';

// 订阅路径
const SUBSCRIPTION_PATH = '/sub'; // 例如 /vless-config, /getnodes etc.

// --- Log Helpers ---
const log = (...args) => console.log(`[${new Date().toISOString()}]`, ...args);
const errorLog = (...args) => console.error(`[${new Date().toISOString()}] ERROR:`, ...args);

if (SERVER_PUBLIC_DOMAIN === 'your-domain.com') {
    log("警告: SERVER_PUBLIC_DOMAIN 可能未正确配置。订阅链接可能无法正常工作。");
    log(`请通过 DOMAIN 环境变量或在代码中修改 SERVER_PUBLIC_DOMAIN。`);
}

log("VLESS 服务器配置:");
log(` - 端口 (PORT): ${PORT}`);
log(` - WebSocket 路径 (VLESS_PATH): ${VLESS_PATH}`);
log(` - 允许的 UUIDs (字符串): ${ALLOWED_UUIDS.join(', ')}`);
log(` - 公开域名 (SERVER_PUBLIC_DOMAIN): ${SERVER_PUBLIC_DOMAIN}`);
log(` - 订阅路径 (SUBSCRIPTION_PATH): ${SUBSCRIPTION_PATH}`);
log(` - 备注前缀 (SERVER_REMARKS_PREFIX): ${SERVER_REMARKS_PREFIX}`);


// --- HTTP Server ---
const httpServer = http.createServer((req, res) => {
    const clientIpForHttp = req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'N/A';

    if (req.url === '/' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`VLESS WebSocket 服务正在运行。\nWebSocket 路径: ${VLESS_PATH}\n订阅地址 (HTTPS): https://${SERVER_PUBLIC_DOMAIN}${SUBSCRIPTION_PATH}\n`);
    } else if (req.url === SUBSCRIPTION_PATH && req.method === 'GET') {
        log(`[${clientIpForHttp}] 收到订阅请求: ${req.url}`);

        if (!SERVER_PUBLIC_DOMAIN || SERVER_PUBLIC_DOMAIN === 'your-domain.com') {
            errorLog("SERVER_PUBLIC_DOMAIN 未配置。无法生成订阅链接。");
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end("服务器配置错误: 公开域名未设置，无法生成订阅链接。");
            return;
        }
        if (ALLOWED_UUIDS.length === 0) {
            log(`[${clientIpForHttp}] 没有配置UUID，返回空订阅。`);
            res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end(Buffer.from("").toString('base64'));
            return;
        }

        const vlessLinks = ALLOWED_UUIDS.map((uuid, index) => {
            const encodedPath = encodeURIComponent(VLESS_PATH); // Ensure VLESS_PATH starts with '/'
            const encodedDomain = encodeURIComponent(SERVER_PUBLIC_DOMAIN);
            const remarks = encodeURIComponent(`${SERVER_REMARKS_PREFIX}_${index + 1}_${SERVER_PUBLIC_DOMAIN.split('.')[0]}`); // Add more specific remark

            return `vless://${uuid}@${SERVER_PUBLIC_DOMAIN}:443?encryption=none&security=tls&type=ws&host=${encodedDomain}&path=${encodedPath}&sni=${encodedDomain}#${remarks}`;
        });

        const allLinksString = vlessLinks.join('\n');
        const base64EncodedSubscription = Buffer.from(allLinksString).toString('base64');

        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(base64EncodedSubscription);
        log(`[${clientIpForHttp}] 已发送包含 ${vlessLinks.length} 个链接的订阅内容。`);

    } else if (req.url === VLESS_PATH && req.method === 'GET') {
        res.writeHead(426, { 'Content-Type': 'text/plain; charset=utf-8', 'Upgrade': 'websocket', 'Connection': 'Upgrade' });
        res.end('此端点为 WebSocket 服务，需要 Upgrade 请求头。');
    }
    else {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('路径未找到 (Not Found)');
    }
});

// --- WebSocket Server ---
const wss = new WebSocket.Server({ server: httpServer }); // Will handle upgrades for the path defined by client

wss.on('connection', (ws, req) => {
    // 只有当请求的路径与 VLESS_PATH 匹配时才处理
    if (req.url !== VLESS_PATH) {
        log(`[WebSocket] 拒绝了路径 ${req.url} 的连接 (期望 ${VLESS_PATH})`);
        ws.close(1008, "Invalid path");
        return;
    }

    const clientIp = req.socket.remoteAddress || req.headers['x-forwarded-for'] || 'N/A';
    log(`[${clientIp}] 客户端已连接 WebSocket 到路径: ${req.url}`);

    let targetSocket = null;
    let duplexStream = null;

    ws.once('message', (initialMsg) => {
        if (!(initialMsg instanceof Buffer)) {
            errorLog(`[${clientIp}] 收到非 Buffer 类型的初始消息，关闭连接。`);
            ws.close(1003, "Unsupported data type for initial message");
            return;
        }

        // VLESS Header Structure:
        // [VERSION (1)] [UUID (16)] [ADDON_LEN (1)] [ADDONS (ADDON_LEN)] [CMD (1)] [PORT (2)] [ATYP (1)] [DEST_ADDR (VAR)] [INITIAL_PAYLOAD (VAR)]
        try {
            let offset = 0;

            if (initialMsg.length < 1 + 16 + 1 + 1 + 2 + 1 + 1) { // Min length for IPv4 dest with 1 byte addr
                errorLog(`[${clientIp}] 初始消息过短，长度: ${initialMsg.length}`);
                ws.close(1002, "Protocol error: initial message too short");
                return;
            }

            const vlessVersion = initialMsg[offset]; // Typically 0x00
            offset += 1;
            if (vlessVersion !== 0x00) {
                errorLog(`[${clientIp}] 不支持的 VLESS 版本: ${vlessVersion}`);
                ws.close(1002, "Unsupported VLESS version");
                return;
            }

            const receivedUuidBuffer = initialMsg.subarray(offset, offset + 16);
            offset += 16;

            const isValidUser = parsedAllowedUuids.some(allowedUid => allowedUid.equals(receivedUuidBuffer));
            if (!isValidUser) {
                errorLog(`[${clientIp}] 无效的 UUID: ${uuidStringify(receivedUuidBuffer)}`);
                ws.close(1008, "Invalid UUID");
                return;
            }
            log(`[${clientIp}] UUID 验证通过: ${uuidStringify(receivedUuidBuffer).substring(0, 13)}...`);

            const addonLen = initialMsg[offset];
            offset += 1;
            offset += addonLen; // Skip addons

            if (offset + 1 + 2 + 1 > initialMsg.length) { // CMD + PORT + ATYP
                errorLog(`[${clientIp}] 消息在解析命令/端口/地址类型时过短`);
                ws.close(1002, "Protocol error: message too short for CMD/PORT/ATYP");
                return;
            }

            const command = initialMsg[offset]; // 0x01 for TCP, 0x02 for UDP
            offset += 1;
            if (command !== 0x01) { // Only TCP supported in this example
                errorLog(`[${clientIp}] 不支持的命令: ${command} (仅支持TCP 0x01)`);
                ws.close(1003, "Unsupported command (only TCP 0x01 supported)");
                return;
            }

            const targetPort = initialMsg.readUInt16BE(offset);
            offset += 2;

            const atyp = initialMsg[offset];
            offset += 1;

            let targetHost = '';
            let addressEndOffset = offset;

            if (atyp === 0x01) { // IPv4
                if (offset + 4 > initialMsg.length) { ws.close(1002, "Msg too short for IPv4"); return; }
                targetHost = initialMsg.subarray(offset, offset + 4).join('.');
                addressEndOffset = offset + 4;
            } else if (atyp === 0x02) { // Domain Name
                if (offset + 1 > initialMsg.length) { ws.close(1002, "Msg too short for domain length"); return; }
                const domainLen = initialMsg[offset];
                offset += 1;
                if (offset + domainLen > initialMsg.length) { ws.close(1002, "Msg too short for domain name"); return; }
                targetHost = initialMsg.subarray(offset, offset + domainLen).toString('utf8');
                addressEndOffset = offset + domainLen;
            } else if (atyp === 0x03) { // IPv6
                if (offset + 16 > initialMsg.length) { ws.close(1002, "Msg too short for IPv6"); return; }
                targetHost = initialMsg.subarray(offset, offset + 16)
                    .reduce((acc, cur, i) => acc + (i % 2 === 0 ? (i > 0 ? ':' : '') + cur.toString(16).padStart(2, '0') : cur.toString(16).padStart(2, '0')), '');
                addressEndOffset = offset + 16;
            } else {
                errorLog(`[${clientIp}] 不支持的地址类型: ${atyp}`);
                ws.close(1003, "Unsupported address type");
                return;
            }

            log(`[${clientIp}] 请求连接到目标: ${targetHost}:${targetPort}`);

            // --- 重要: 发送 VLESS 服务端对客户端握手的响应 ---
            // [VLESS Version (same as client sent, typically 0x00), Response Addon Version (typically 0x00)]
            ws.send(Buffer.from([vlessVersion, 0x00]));

            const firstPayload = initialMsg.subarray(addressEndOffset);

            duplexStream = createWebSocketStream(ws, { encoding: 'binary' });

            targetSocket = net.connect(targetPort, targetHost, () => {
                log(`[${clientIp}] 已连接到目标: ${targetHost}:${targetPort}`);
                if (firstPayload.length > 0) {
                    // log(`[${clientIp}] 转发初始负载 (${firstPayload.length} bytes) 到目标`);
                    targetSocket.write(firstPayload);
                }
                // 双向数据流绑定
                duplexStream.pipe(targetSocket).pipe(duplexStream);
            });

            // --- 错误和关闭处理 ---
            duplexStream.on('error', (err) => {
                errorLog(`[${clientIp}] WebSocket 双工流错误: ${err.message}`);
                if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
                // ws is already part of duplexStream, its error/close will be handled
            });
            duplexStream.on('close', () => {
                // log(`[${clientIp}] WebSocket 双工流关闭`);
                if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
            });

            targetSocket.on('error', (err) => {
                errorLog(`[${clientIp}] 目标 (${targetHost}:${targetPort}) 连接错误: ${err.message}`);
                if (duplexStream && !duplexStream.destroyed) duplexStream.destroy();
            });
            targetSocket.on('close', (hadError) => {
                // log(`[${clientIp}] 目标 (${targetHost}:${targetPort}) 连接已关闭${hadError ? ' (因错误)' : ''}`);
                if (duplexStream && !duplexStream.destroyed) duplexStream.destroy();
            });

        } catch (e) {
            errorLog(`[${clientIp}] 处理 VLESS 初始消息时发生严重错误: ${e.message}\n${e.stack}`);
            if (ws.readyState === WebSocket.OPEN) {
                ws.close(1002, "Protocol error during initial message processing");
            }
            if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
            if (duplexStream && !duplexStream.destroyed) duplexStream.destroy();
        }
    });

    ws.on('error', (err) => {
        errorLog(`[${clientIp}] 客户端 WebSocket 错误: ${err.message}`);
        if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
        if (duplexStream && !duplexStream.destroyed) duplexStream.destroy();
    });

    ws.on('close', (code, reason) => {
        const reasonStr = reason ? reason.toString() : 'N/A';
        log(`[${clientIp}] 客户端 WebSocket 已关闭。Code: ${code}, Reason: ${reasonStr}`);
        if (targetSocket && !targetSocket.destroyed) targetSocket.destroy();
        if (duplexStream && !duplexStream.destroyed) duplexStream.destroy();
    });
});

// --- 启动服务器 ---
httpServer.listen(PORT, '0.0.0.0', () => { // 监听 0.0.0.0 确保外部可以访问
    log(`HTTP 服务器已启动，正在监听端口: ${PORT}`);
    log(`可以通过 https://${SERVER_PUBLIC_DOMAIN} (假设外部已配置 SSL 和反向代理到此端口) 访问。`);
});

process.on('SIGINT', () => {
    log("收到 SIGINT，准备关闭服务器...");
    wss.close(() => {
        log("WebSocket 服务器已关闭。");
        httpServer.close(() => {
            log("HTTP 服务器已关闭。");
            process.exit(0);
        });
    });
    // 设置超时强制退出
    setTimeout(() => {
        errorLog("关闭超时，强制退出。");
        process.exit(1);
    }, 5000);
});

process.on('unhandledRejection', (reason, promise) => {
    errorLog('未处理的 Promise Rejection:', reason);
});
process.on('uncaughtException', (err) => {
    errorLog('未捕获的异常:', err);
    process.exit(1); // 通常需要重启
});
