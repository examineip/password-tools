'use strict';
const fs = require('fs');
const path = require('path');
const pt = require('../password-tools.js');

let pass = 0, fail = 0;
function eq(name, got, want) {
  const g = JSON.stringify(got), w = JSON.stringify(want);
  if (g === w) pass++;
  else { fail++; console.log('FAIL ' + name + '\n  got  ' + g + '\n  want ' + w); }
}
function ok(name, cond, detail) { eq(name + (detail ? ' (' + detail + ')' : ''), !!cond, true); }

(async () => {
  // --- wordlist is the EFF list, unmodified ---
  const eff = fs.readFileSync(path.join(__dirname, 'eff_large_wordlist.txt'), 'utf8')
    .split('\n').filter(l => l.includes('\t')).map(l => l.split('\t')[1].trim());
  eq('wordlist length', pt.WORDS.length, 7776);
  eq('wordlist identical to EFF file, same order', pt.WORDS.join(','), eff.join(','));
  eq('wordlist unique', new Set(pt.WORDS).size, 7776);

  // --- randInt: in range, and not modulo-biased ---
  let inRange = true;
  for (let i = 0; i < 2000; i++) { const v = pt.randInt(7); if (v < 0 || v > 6) inRange = false; }
  ok('randInt range', inRange);
  eq('randInt(0)', pt.randInt(0), 0);
  // Chi-square over 6 buckets, 60,000 draws. df=5; p=0.001 critical value is 20.5.
  const N = 60000, K = 6, counts = new Array(K).fill(0);
  for (let i = 0; i < N; i++) counts[pt.randInt(K)]++;
  const chi = counts.reduce((s, c) => s + Math.pow(c - N / K, 2) / (N / K), 0);
  ok('randInt uniform', chi < 20.5, 'chi2=' + chi.toFixed(2));

  // --- generators ---
  const g = pt.generatePassword(20, { upper: true, lower: true, digits: true, symbols: false, noAmbiguous: false });
  eq('password length', g.password.length, 20);
  eq('password pool', g.pool, 62);
  eq('password bits', Math.round(g.bits * 100) / 100, Math.round(20 * Math.log2(62) * 100) / 100);
  ok('password only uses pool', /^[A-Za-z0-9]{20}$/.test(g.password));
  const amb = pt.generatePassword(200, { upper: true, lower: true, digits: true, noAmbiguous: true });
  ok('no ambiguous characters', !/[IlO01o]/.test(amb.password));
  eq('no character classes', pt.generatePassword(10, {}), null);

  const p = pt.generatePassphrase(6, '-', false, false);
  eq('passphrase words', p.password.split('-').filter(Boolean).length >= 6, true);   // a few EFF words contain '-'
  eq('passphrase bits', Math.round(p.bits * 100) / 100, Math.round(6 * Math.log2(7776) * 100) / 100);
  const pn = pt.generatePassphrase(4, ' ', true, true);
  ok('capitalised + number', /^[A-Z][a-z-]+ [A-Z][a-z-]+ [A-Z][a-z-]+ [A-Z][a-z-]+ \d{1,2}$/.test(pn.password), pn.password);
  eq('number adds log2(100)', Math.round((pn.bits - 4 * Math.log2(7776)) * 100) / 100, Math.round(Math.log2(100) * 100) / 100);

  // --- strength estimates: patterns attackers use are scored accordingly ---
  eq('common password', pt.estimate('password').verdict, 'terrible');
  eq('common + digits', pt.estimate('Password123').verdict, 'terrible');
  ok('leet word stays weak', pt.estimate('Tr0ub4dor&3').bits < 40, pt.estimate('Tr0ub4dor&3').bits.toFixed(1));
  ok('dictionary word + suffix is weak', pt.estimate('dolphin2024').bits < 40);
  ok('keyboard run penalised', pt.estimate('qwertyuiop77').bits < pt.estimate('qwertyuiop77').ceiling);
  eq('digits only', pt.estimate('8475936102').verdict, 'weak');
  eq('repeated character', pt.estimate('aaaaaaaaaaaaaaaa').verdict, 'terrible');
  eq('random 20 chars', pt.estimate('vR7#qLx2!mZp9@Tb4$Wk').verdict, 'excellent');
  const phrase = pt.estimate('correct horse battery staple');
  ok('passphrase modelled as words', phrase.bits <= 4 * 13 + 6, phrase.bits.toFixed(1));
  ok('passphrase note', phrase.notes.some(n => /passphrase/i.test(n)));
  eq('empty', pt.estimate('').verdict, 'empty');
  // Regression: random strings with symbols must not be mistaken for passphrases.
  ['vR7#qLx2!mZp9@Tb4$Wk', 'k9$Tq@2wXz!7Lm#pR4vB', 'Zx8!qw3@Lk9#Pm2$Rt7^'].forEach(s =>
    ok('random not a passphrase: ' + s, pt.estimate(s).verdict === 'excellent', pt.estimate(s).bits.toFixed(1)));
  // Regression: an all-digit PIN must not be read as a leet-spelled word.
  ok('digits are not a leet word', !pt.estimate('847593610274').notes.some(n => /pronounceable/.test(n)));
  eq('real passphrase still detected', pt.estimate('river-candle-orbit-tulip').notes.some(n => /passphrase/i.test(n)), true);

  // --- crack times ---
  eq('instant', pt.crackTimes(10).fast, 'instantly');
  ok('slow hash takes longer', /year|centur|forever/.test(pt.crackTimes(60).slow), pt.crackTimes(60).slow);
  eq('huge', pt.humanTime(Infinity), 'longer than the universe has existed');

  // --- SHA-1 against known vectors ---
  eq('sha1 "password"', await pt.sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
  eq('sha1 "abc" (FIPS 180)', await pt.sha1Hex('abc'), 'A9993E364706816ABA3E25717850C26C9CD0D89D');
  eq('sha1 ""', await pt.sha1Hex(''), 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');

  // --- breach check: only the 5-character prefix leaves the machine ---
  let requested = null;
  const fakeFetch = (url, init) => {
    requested = { url, init };
    const body = [
      '003D68EB55068C33ACE09247EE4C639306B:3',
      '1E4C9B93F3F0682250B6CF8331B7EE68FD8:9659365',   // suffix of SHA1("password")
      '00000000000000000000000000000000000:0'           // padding line (Add-Padding) has count 0
    ].join('\r\n');
    return Promise.resolve({ ok: true, text: () => Promise.resolve(body) });
  };
  const hit = await pt.checkBreach('password', { fetch: fakeFetch });
  eq('only the prefix is sent', requested.url, 'https://api.pwnedpasswords.com/range/5BAA6');
  eq('padding requested', requested.init.headers['Add-Padding'], 'true');
  eq('found with count', [hit.found, hit.count], [true, 9659365]);
  const miss = await pt.checkBreach('a-password-nobody-uses-7Qx!', { fetch: fakeFetch });
  eq('not found', miss.found, false);
  let threw = false;
  try { await pt.checkBreach('x', { fetch: () => Promise.resolve({ ok: false, text: () => Promise.resolve('') }) }); } catch (e) { threw = true; }
  eq('API error surfaces', threw, true);

  console.log(`${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
})();
