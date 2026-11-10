// Audit item 8: an unrated title showed a rating of 0.
//
// Xtream sends `rating: "0"` for content nobody has rated, and the meta routes
// tested the value for truthiness — which the string "0" passes — so Stremio
// rendered a 0 rating instead of omitting it.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const { ratingOf } = require('./support/internals.js');

test('a real rating survives, as a string', () => {
    expect(ratingOf('7.5')).toBe('7.5');
    expect(ratingOf(8)).toBe('8');
    expect(ratingOf(' 6.2 ')).toBe('6.2');
});

test('the shapes an unrated title arrives in are no rating at all', () => {
    for (const value of ['0', 0, '0.0', '', '  ', 'N/A', null, undefined, -1, NaN, Infinity]) {
        expect(ratingOf(value), `${JSON.stringify(value)} rendered as a rating`).toBeUndefined();
    }
});

test('only strings and numbers count', () => {
    // Number(true) is 1 and Number([7]) is 7; neither is a rating a provider sent.
    for (const value of [true, [7], { rating: 7 }]) {
        expect(ratingOf(value)).toBeUndefined();
    }
});
