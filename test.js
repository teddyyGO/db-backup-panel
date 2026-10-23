'use strict';
// Minimal self-checks for the security-sensitive helpers. Run: npm test
process.env.APP_PASSWORD = process.env.APP_PASSWORD || 'test-password-123';
process.env.APP_SECRET = process.env.APP_SECRET || 'x'.repeat(64);
process.env.DATA_DIR = require('path').join(require('os').tmpdir(), 'db-backuper-test');

const test = require('node:test');
const assert = require('node:assert');
const s = require('./server');

test('connection string parsing rejects option injection', () => {
  assert.equal(s.parseMysqlConn('mysql://u:p@h:3306/db').database, 'db');
  assert.throws(() => s.parseMysqlConn('mysql://u:p@h/--result-file=x'));
  assert.throws(() => s.parseMysqlConn('postgres://u:p@h/db'));
});

test('option-file quoting escapes newlines and quotes', () => {
  assert.equal(s.cnfQuote('a"b\\c\nd'), '"a\\"b\\\\c\\nd"');
});

test('backup names cannot escape the backup dir', () => {
  assert.equal(s.resolveBackup('../config.json'), null);
  assert.equal(s.resolveBackup('..\\x.sql.gz'), null);
  assert.equal(s.resolveBackup('nope.txt'), null);
});

test('encryption round-trips', () => {
  assert.equal(s.decryptSecret(s.encryptSecret('secret')), 'secret');
});

test('table list keeps only safe identifiers', () => {
  assert.deepEqual(s.parseTableList('logs, --evil; a$b x.y'), ['logs', 'a$b']);
});
