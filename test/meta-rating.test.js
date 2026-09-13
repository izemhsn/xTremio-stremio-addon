// Audit item 8: an unrated title showed a rating of 0.
//
// Xtream sends `rating: "0"` for content nobody has rated, and the meta routes
// tested the value for truthiness — which the string "0" passes — so Stremio
// rendered a 0 rating instead of omitting it.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const test = require('node:test');
const assert = require('node:assert');

const { ratingOf } = require('../index.js');

test('a real rating survives, as a string', () => {
    assert.equal(ratingOf('7.5'), '7.5');
    assert.equal(ratingOf(8), '8');
    assert.equal(ratingOf(' 6.2 '), '6.2');
});

test('the shapes an unrated title arrives in are no rating at all', () => {
    for (const value of ['0', 0, '0.0', '', '  ', 'N/A', null, undefined, -1, NaN, Infinity]) {
        assert.equal(ratingOf(value), undefined, `${JSON.stringify(value)} rendered as a rating`);
    }
});

test('only strings and numbers count', () => {
    // Number(true) is 1 and Number([7]) is 7; neither is a rating a provider sent.
    for (const value of [true, [7], { rating: 7 }]) {
        assert.equal(ratingOf(value), undefined);
    }
});
