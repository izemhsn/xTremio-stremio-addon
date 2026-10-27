// D2 — the Node floor and the undici check disagreed.
//
// The pinned connection agent comes from the undici dependency (7.x), while fetch()
// comes from the undici Node bundles. warnOnUndiciMismatch compared the two majors and
// warned on any difference, so on the documented Node 20.18.1 floor — which bundles
// undici 6.20 — it printed "Outbound requests will fail". Measured, they do not: undici
// 6 and 7 interoperate in both directions, and the full suite passes on Node 20.18.1,
// 22 and 24. The pairing that does fail is an undici 8 agent with an older fetch,
// which rejects every request with "invalid onRequestStart method".
//
// ALLOW_PRIVATE_NETWORKS is left unset so the real check has a pinned agent to judge.
process.env.CONFIG_SECRET = 'test-secret-for-unit-tests';

const { warnOnUndiciMismatch } = require('./support/internals.js');

function check(bundled, dependency, pinned = true) {
    const warnings = [];
    const ok = warnOnUndiciMismatch({ warn: (message) => warnings.push(message) }, { pinned, bundled, dependency });
    return { ok, warnings };
}

test('the documented Node 20.18.1 floor is not told its requests will fail', () => {
    expect(check('6.20.0', '7.29.1'), 'Node 20.18.1').toStrictEqual({ ok: true, warnings: [] });
    expect(check('6.28.0', '7.29.1'), 'Node 22').toStrictEqual({ ok: true, warnings: [] });
});

test('the same major is fine', () => {
    expect(check('7.25.0', '7.29.1')).toStrictEqual({ ok: true, warnings: [] });
});

test('undici 6 and 7 interoperate in both directions', () => {
    expect(check('7.25.0', '6.28.1')).toStrictEqual({ ok: true, warnings: [] });
});

test('an undici 8 agent with an older fetch is warned about, naming the failure', () => {
    const { ok, warnings } = check('7.25.0', '8.10.2');
    expect(ok).toBe(false);
    expect(warnings.length).toBe(1);
    expect(warnings[0]).toMatch(/invalid onRequestStart method/);
});

test('a runtime bundling a newer undici than any verified is warned about as unverified', () => {
    const { ok, warnings } = check('8.1.0', '7.29.1');
    expect(ok).toBe(false);
    expect(warnings[0]).toMatch(/not been verified/);
});

test('there is nothing to judge without a pinned agent', () => {
    // With ALLOW_PRIVATE_NETWORKS on, no pinned agent exists and fetch uses its own.
    expect(check('8.1.0', '7.29.1', false)).toStrictEqual({ ok: true, warnings: [] });
});

test('the runtime this suite is running on, with the shipped dependency, passes', () => {
    // Run on Node 20.18.1 this is the finding itself; on a future Node that bundles a
    // pairing nobody has measured, it is the signal to measure it.
    const warnings = [];
    expect(warnOnUndiciMismatch({ warn: (message) => warnings.push(message) }, { pinned: true })).toBe(true);
    expect(warnings).toStrictEqual([]);
});
