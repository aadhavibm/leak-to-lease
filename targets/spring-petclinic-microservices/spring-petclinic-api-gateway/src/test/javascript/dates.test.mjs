import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = new URL('../../main/resources/static/scripts/utils/dates.js', import.meta.url);
const moduleUrl = `data:text/javascript;base64,${Buffer.from(readFileSync(source, 'utf8')).toString('base64')}`;

for (const timezone of ['UTC', 'America/Los_Angeles', 'America/Chicago', 'Asia/Tokyo', 'Pacific/Apia']) {
    test(`calendar dates stay unchanged in ${timezone}`, () => {
        const script = `
            import assert from 'node:assert/strict';
            const { formatDate, toDateInputValue, today } = await import(${JSON.stringify(moduleUrl)});
            assert.equal(formatDate('2020-01-01'), '2020 Jan 01');
            assert.equal(formatDate('2024-02-29'), '2024 Feb 29');
            assert.equal(formatDate('2011-12-30'), '2011 Dec 30');
            assert.equal(toDateInputValue('2020-01-01'), '2020-01-01');
            assert.equal(toDateInputValue('0001-01-01'), '0001-01-01');
            assert.equal(formatDate(null), '');
            assert.equal(toDateInputValue(''), '');
            assert.throws(() => formatDate('2023-02-29'), RangeError);
            assert.throws(() => toDateInputValue('2024-13-01'), RangeError);
            assert.throws(() => formatDate('not-a-date'), RangeError);
            const local = new Date(2026, 10, 25, 23, 30);
            assert.equal(formatDate(local), '2026 Nov 25');
            assert.equal(toDateInputValue(local), '2026-11-25');
            const now = new Date();
            assert.equal(today(), toDateInputValue(now));
        `;
        const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
            env: { ...process.env, TZ: timezone },
            encoding: 'utf8'
        });
        assert.equal(result.status, 0, result.stderr);
    });
}
