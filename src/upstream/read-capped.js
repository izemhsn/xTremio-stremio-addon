// Reading an upstream body without letting it decide how much memory this
// process uses.
//
// The cap is on what a body *parses to*, not only on its size: a 16 MB
// `[{},{},…]` body retained 341 MB of heap after GC, 21x, against 1.1x for a
// realistic list. So each chunk is weighed as it arrives — the structural bytes
// `{`, `[` and `,` by PARSED_WEIGHT, plus half a byte per body byte for string
// payload — and a body estimated past MAX_PARSED_TO_BODY_RATIO times its byte cap
// is refused mid-download, before JSON.parse builds any of it.
//
// estimateBytes lives here rather than with the cache because it reads the count
// this reader recorded. Weighing a parsed value by sampling is the fallback, not
// the method: a sample's positions follow from the list's length and can be
// steered, so a list whose sampled items are empty and whose others are nested
// weighs far below its cost.

// Only for discardBody, so that "every path that abandons a response cancels its
// body" stays one implementation rather than a rule copied here. safe-fetch
// requires nothing from this module, so the edge adds no cycle.
const { discardBody } = require('../net/safe-fetch.js');

// The upstream host is supplied by the user and reachable before any
// authentication, so an unbounded res.json() lets a hostile or broken provider
// stream until the process runs out of memory. Large providers legitimately
// return tens of MB for get_vod_streams, so the cap is generous but finite.
const MAX_UPSTREAM_BYTES = Math.max(1, Number(process.env.MAX_UPSTREAM_MB) || 64) * 1024 * 1024;

// What a JSON body will cost once parsed, estimated from its bytes as they arrive.
// Shape matters more than size: a 16 MB realistic list retained 18 MB of heap, a
// 16 MB [{},{},…] body 341 MB. The structural bytes are weighed by what the value
// behind them costs — `{` 56, `[` 32, `,` 8 — plus half a byte per body byte. Fitted
// across eleven shapes: 0.78-1.27x of real heap for realistic bodies, at or above it
// for hostile ones. Counted inside strings too; over-counting is the safe side.
const PARSED_WEIGHT = new Uint8Array(256);
PARSED_WEIGHT[0x7b] = 56; // {
PARSED_WEIGHT[0x5b] = 32; // [
PARSED_WEIGHT[0x2c] = 8;  // ,

// How large a body may be *estimated* to parse to, relative to its byte cap. Real
// bodies estimate at 1.0-1.3x and hit the byte cap first; a hostile one is refused
// mid-download. Keep it above what real bodies estimate at.
const MAX_PARSED_TO_BODY_RATIO = 2;

// The estimate each parsed payload arrived with, so the caches can weigh it from
// every byte of its body rather than from a sample. Keyed by the parsed value, so
// an entry lives exactly as long as the value does.
const parsedSizeEstimates = new WeakMap();

// `onChunk` is called once per chunk read, which is how xtremioGet's idle deadline
// knows the download is still moving.
async function readJsonCapped(res, label, maxBytes = MAX_UPSTREAM_BYTES, { onChunk = null } = {}) {
    // Trust a declared length to reject early, before reading a single byte.
    const declared = Number(res.headers?.get?.('content-length'));
    if (Number.isFinite(declared) && declared > maxBytes) {
        // Refused before a byte is read, which means the body is still pending:
        // cancel it, or undici keeps that connection out of its pool until the
        // response is collected (audit F3). The two caps below already cancel
        // through the reader; this is the one exit that never takes one.
        discardBody(res);
        throw new Error(`${label} response too large: ${declared} bytes exceeds ${maxBytes}`);
    }
    // A stub or a body-less response has nothing to meter; fall back.
    if (!res.body || typeof res.body.getReader !== 'function') return res.json();

    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    let structural = 0;
    const maxParsedBytes = maxBytes * MAX_PARSED_TO_BODY_RATIO;
    // Yield to the event loop once per megabyte. With a buffered body, read()
    // resolves as microtasks, so without this the count ran as one block merged
    // with the parse (a 25 MB list's longest stall: 247 ms without, 128 ms with).
    const YIELD_EVERY_BYTES = 1024 * 1024;
    let nextYieldAt = YIELD_EVERY_BYTES;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
            // Stop pulling from the socket rather than finishing the download.
            await reader.cancel().catch(() => {});
            throw new Error(`${label} response exceeded ${maxBytes} bytes`);
        }
        // Checked per chunk, like the byte cap, so a hostile body is refused before
        // the rest of it arrives rather than after JSON.parse has inflated it.
        for (let i = 0; i < value.length; i++) structural += PARSED_WEIGHT[value[i]];
        if (structural + total / 2 > maxParsedBytes) {
            await reader.cancel().catch(() => {});
            throw new Error(
                `${label} response is shaped to parse to more than ${Math.round(maxParsedBytes / 1048576)} MB ` +
                `after ${total} bytes; refusing it before parsing`
            );
        }
        // Kept as the Uint8Array it arrived as: Buffer.concat accepts those, and
        // Buffer.from(value) copied every chunk of the body a second time.
        chunks.push(value);
        if (onChunk) onChunk();
        if (total >= nextYieldAt) {
            nextYieldAt = total + YIELD_EVERY_BYTES;
            await new Promise((resolve) => setImmediate(resolve));
        }
    }
    // Four statements, not one expression: each step copies the body, and dropping
    // each reference as the next copy appears keeps one copy alive at parse time
    // instead of three (measured ~3x -> ~1x on a 21 MB body).
    let buf = Buffer.concat(chunks);
    chunks.length = 0;
    const text = buf.toString('utf8');
    buf = null;
    const data = JSON.parse(text);
    if (data !== null && typeof data === 'object') parsedSizeEstimates.set(data, structural + total / 2);
    return data;
}

// What a cached value costs in memory — estimated heap, not serialized size (`{}`
// serializes to 2 bytes and occupies 56). The weights are readJsonCapped's.
function estimateBytes(value) {
    // A payload read from upstream was weighed from every byte of its body, which
    // no sample can match, and a sample's positions can be steered.
    if (value !== null && typeof value === 'object') {
        const measured = parsedSizeEstimates.get(value);
        if (measured !== undefined) return Math.round(measured);
    }

    // Everything else is sampled: serializing a whole list would double peak
    // memory to measure memory.
    if (!Array.isArray(value)) {
        try {
            return Math.round(weighJson(JSON.stringify(value)));
        } catch {
            return 0;
        }
    }
    if (!value.length) return 0;

    const step = Math.max(1, Math.floor(value.length / 20));
    let sampled = 0;
    let counted = 0;
    for (let i = 0; i < value.length; i += step) {
        try {
            sampled += weighJson(JSON.stringify(value[i]));
        } catch {
            // A circular or unserializable item tells us nothing; skip it.
        }
        counted++;
    }
    if (!counted) return 0;
    // Plus the list's own slots (the commas the streamed estimate counts), so the
    // two paths agree.
    return Math.round((sampled / counted) * value.length + PARSED_WEIGHT[0x2c] * value.length);
}

// The streaming estimate, applied to text already in hand.
function weighJson(text) {
    if (typeof text !== 'string') return 0;
    let structural = 0;
    for (let i = 0; i < text.length; i++) {
        const c = text.charCodeAt(i);
        if (c < 256) structural += PARSED_WEIGHT[c];
    }
    return structural + text.length / 2;
}

async function readTextCapped(body, maxBytes) {
    const reader = body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maxBytes) {
            await reader.cancel().catch(() => {});
            throw new Error(`playlist exceeded ${maxBytes} bytes`);
        }
        chunks.push(value);
    }
    return Buffer.concat(chunks).toString('utf8');
}

module.exports = {
    MAX_UPSTREAM_BYTES,
    MAX_PARSED_TO_BODY_RATIO,
    PARSED_WEIGHT,
    parsedSizeEstimates,
    readJsonCapped,
    readTextCapped,
    estimateBytes,
    weighJson
};
