// GET /manifest.json and GET /:config/manifest.json
//
// The manifest is the first thing Stremio fetches: it says which catalogs this
// addon offers and which ids it can answer meta and stream requests for. Without
// a config token it describes an unconfigured addon, which Stremio answers by
// sending the user to /configure.
const express = require('express');

const { decodeConfig } = require('../config/token.js');
const { getManifest } = require('../manifest.js');

const router = express.Router();

router.get('/manifest.json', async (req, res) => {
    res.json(await getManifest(null));
});

router.get('/:config/manifest.json', async (req, res) => {
    const cfg = decodeConfig(req.params.config);
    res.json(await getManifest(cfg));
});

module.exports = { router };
