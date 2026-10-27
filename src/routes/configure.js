// GET  /configure            — the setup form
// GET  /:config/configure    — the same form, from an installed addon's Configure button
// POST /configure            — check the credentials and show the install link
//
// This is the only page that handles a plaintext password, so it gets the
// strictest headers in the app (see setPrivateHeaders).
const crypto = require('node:crypto');
const express = require('express');

const { decodeConfig } = require('../config/token.js');
const { asString, normalizeUrl } = require('../helpers.js');
const { hostnameOf, panelHostAllowed } = require('../config/panel-allowlist.js');
const { validateXtremioCredentials } = require('../config/validate.js');
const { rateLimitConfigure } = require('../config/rate-limit.js');
const { renderConfigPage } = require('../pages/configure.js');
const { getBaseUrl } = require('../http/request.js');
const { logRouteError } = require('../http/errors.js');

const router = express.Router();

// Only this route reads a form, so the body parser is mounted here rather than
// for the whole app. The form is three flat string fields, so extended parsing
// (nested objects and arrays) is off.
const parseConfigureForm = express.urlencoded({ extended: false, limit: '8kb' });

// The page echoes a submitted password and embeds the install token, so it is
// kept out of caches and Referer headers, and cannot be framed (clickjacking).
// The Content-Security-Policy is a second line of defence behind escapeHtml:
// nothing external loads, and scripts run only with a per-response nonce, so
// inline on* handlers do not run either. Returns the nonce, which must be passed
// to renderConfigPage.
function setPrivateHeaders(res) {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');

    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Content-Security-Policy', [
        "default-src 'none'",
        `script-src 'nonce-${nonce}'`,
        "style-src 'unsafe-inline'",
        // form-action does not fall back to default-src, so the page's own POST
        // has to be allowed explicitly or the form silently stops submitting.
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'"
    ].join('; '));
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return nonce;
}

// The form is prefilled from an existing config token, but never with the
// password: the token is the install URL Stremio syncs, and putting its
// password into the page would hand a working credential to whoever holds that
// URL.
function sendConfigurePage(req, res, token) {
    const nonce = setPrivateHeaders(res);
    const existing = decodeConfig(token) || {};
    res.send(renderConfigPage({
        serverUrl: existing.serverUrl || '',
        username: existing.username || '',
        baseUrl: getBaseUrl(req),
        nonce
    }));
}

router.get('/configure', (req, res) => sendConfigurePage(req, res, req.query.config));

// Stremio's Configure button on an installed addon replaces `manifest.json`
// with `configure` in the addon URL, so it lands here rather than on
// /configure. The form still posts to /configure.
router.get('/:config/configure', (req, res) => sendConfigurePage(req, res, req.params.config));

// "server URL, username and password" from the names of the missing fields.
function describeMissing(missing) {
    if (missing.length === 1) return missing[0];
    return `${missing.slice(0, -1).join(', ')} and ${missing[missing.length - 1]}`;
}

router.post('/configure', parseConfigureForm, async (req, res) => {
    const nonce = setPrivateHeaders(res);
    // req.body may be undefined, and its fields are not guaranteed to be strings.
    const body = req.body || {};
    const rawServerUrl = asString(body.serverUrl).trim().replace(/\/+$/, '');
    const username = asString(body.username);
    const password = asString(body.password);
    const render = (status, serverUrl = rawServerUrl) => res.send(renderConfigPage({
        serverUrl,
        username,
        password,
        status,
        baseUrl: getBaseUrl(req),
        nonce
    }));
    const fail = (error) => render({ valid: false, error });

    const limit = rateLimitConfigure(req);
    if (!limit.allowed) {
        res.status(429);
        res.setHeader('Retry-After', String(limit.retryAfter));
        return fail(`Too many attempts. Try again in ${limit.retryAfter} second${limit.retryAfter === 1 ? '' : 's'}.`);
    }

    // The form marks every field `required`, but a direct POST can still skip
    // one, and should be told which.
    const missing = [
        !rawServerUrl && 'server URL',
        !username && 'username',
        !password && 'password'
    ].filter(Boolean);
    if (missing.length) return fail(`Please enter your ${describeMissing(missing)}.`);

    // Checked before any request is made, since checking the credentials is
    // itself a request to the host the caller chose. The reply does not list the
    // allowed hosts — whether to publish that is the operator's decision.
    if (!panelHostAllowed(rawServerUrl)) {
        console.warn(
            `[configure] refused ${JSON.stringify(hostnameOf(rawServerUrl) || rawServerUrl.slice(0, 100))}: ` +
            'not in ALLOWED_PANEL_HOSTS'
        );
        return fail('This instance only accepts accounts from specific providers, and that server is not one of them.');
    }

    try {
        const validation = await validateXtremioCredentials(rawServerUrl, username, password);
        render(validation, validation.valid
            ? (validation.resolvedUrl || normalizeUrl(rawServerUrl))
            : rawServerUrl);
    } catch (e) {
        // validateXtremioCredentials reports every provider and network failure
        // as { valid: false }, so anything thrown is a bug in this server.
        logRouteError('configure', e);
        fail('Something went wrong. Please try again.');
    }
});

module.exports = { router };
