#!/usr/bin/env node
const http = require("http");
const fs = require("fs");
const path = require("path");

const PORT = 8899;
const PROJECT_DIR = path.join(__dirname, "..");

// Load env
function loadEnv() {
    const envFile = path.join(PROJECT_DIR, "configs", "dorakula.env");
    if (fs.existsSync(envFile)) {
        for (const line of fs.readFileSync(envFile, "utf8").split("\n")) {
            const t = line.trim();
            if (!t || t.startsWith("#")) continue;
            const i = t.indexOf("=");
            if (i > 0) {
                const key = t.slice(0, i).trim();
                if (!process.env[key]) process.env[key] = t.slice(i + 1).trim();
            }
        }
    }
}
loadEnv();

const OLLAMA_URL = process.env.DORAKULA_OLLAMA_URL || "http://localhost:11434";
const OLLAMA_MODEL = process.env.DORAKULA_OLLAMA_MODEL || "tinyllama:latest";
const OLLAMA_TIMEOUT = (parseInt(process.env.DORAKULA_OLLAMA_TIMEOUT) || 120) * 1000;
let stats = { ollama_calls: 0, failures: 0, start_time: Date.now() };

async function callOllama(messages, model, temperature, maxTokens) {
    const payload = JSON.stringify({
        model: model || OLLAMA_MODEL, messages, stream: false,
        keep_alive: 0, options: { temperature: temperature || 0.3, num_predict: maxTokens || 4096 }
    });
    return new Promise((resolve) => {
        const url = new URL(OLLAMA_URL + "/api/chat");
        const mod = url.protocol === "https:" ? require("https") : require("http");
        const req = mod.request({
            hostname: url.hostname, port: url.port, path: url.pathname, method: "POST",
            headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
        }, (res) => {
            let data = "";
            res.on("data", c => data += c);
            res.on("end", () => {
                try {
                    const p = JSON.parse(data);
                    if (p && p.message && p.message.content) {
                        stats.ollama_calls++;
                        unloadModel(model || OLLAMA_MODEL);
                        resolve({ success: true, content: p.message.content, provider: "ollama", model: model || OLLAMA_MODEL });
                    } else {
                        stats.failures++;
                        resolve({ success: false, error: "No content from Ollama" });
                    }
                } catch (e) { stats.failures++; resolve({ success: false, error: e.message }); }
            });
        });
        req.on("error", (e) => { stats.failures++; resolve({ success: false, error: e.message }); });
        req.setTimeout(OLLAMA_TIMEOUT, () => { req.destroy(); stats.failures++; resolve({ success: false, error: "Ollama timeout" }); });
        req.write(payload);
        req.end();
    });
}


async function unloadModel(model) {
    const payload = JSON.stringify({ model: model || OLLAMA_MODEL, keep_alive: 0 });
    return new Promise((resolve) => {
        const url = new URL(OLLAMA_URL + "/api/generate");
        const mod = url.protocol === "https:" ? require("https") : require("http");
        const req = mod.request({
            hostname: url.hostname, port: url.port, path: url.pathname, method: "DELETE",
            headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(payload) }
        }, (res) => { let d = ""; res.on("data", c => d += c); res.on("end", () => resolve()); });
        req.on("error", () => resolve());
        req.write(payload);
        req.end();
    });
}

const server = http.createServer((req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") { res.writeHead(200); res.end(); return; }
    if (req.method === "GET" && req.url === "/health") {
        res.writeHead(200); res.end(JSON.stringify({ status: "ok", provider: "ollama", model: OLLAMA_MODEL, stats, uptime_sec: Math.floor((Date.now() - stats.start_time) / 1000) })); return;
    }
    if (req.method === "POST" && req.url === "/chat") {
        let body = "";
        req.on("data", c => body += c);
        req.on("end", async () => {
            try {
                const d = JSON.parse(body);
                const msgs = d.messages || [];
                if (!msgs.length) { res.writeHead(400); res.end(JSON.stringify({ success: false, error: "messages required" })); return; }
                const r = await callOllama(msgs, d.model, d.temperature, d.max_tokens);
                res.writeHead(r.success ? 200 : 502);
                res.end(JSON.stringify(r));
            } catch (e) { res.writeHead(400); res.end(JSON.stringify({ success: false, error: e.message })); }
        });
        return;
    }
    if (req.method === "GET" && req.url === "/stats") { res.writeHead(200); res.end(JSON.stringify({ success: true, stats })); return; }
    res.writeHead(404); res.end(JSON.stringify({ error: "Not found" }));
});

console.log("[AI-SERVICE] Ollama-only microservice on port " + PORT);
console.log("[AI-SERVICE] Model: " + OLLAMA_MODEL);
server.listen(PORT, "127.0.0.1", () => { console.log("[AI-SERVICE] Ready!"); });
