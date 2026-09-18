# password-tools

An **honest password strength estimate**, **cryptographically random** password and passphrase
generators, and a **private breach check** against Have I Been Pwned.

Browser and Node 18+, no dependencies. It powers the
[Password Tools on ExamineIP](https://tools.examineip.com/password-tools/).

```js
const pt = require('./password-tools');   // browser: load eff-wordlist.js, then password-tools.js → window.passwordTools

pt.estimate('Tr0ub4dor&3');             // { bits: 18, verdict: 'terrible', notes: ['Under the digits and symbols this is a pronounceable word…'] }
pt.estimate('vR7#qLx2!mZp9@Tb4$Wk');    // { bits: 131.4, verdict: 'excellent', … }

pt.generatePassphrase(6, '-');          // { password: 'unquote-chapped-hunter-chemicals-wiry-unengaged', bits: 77.5 }
await pt.checkBreach('password');       // { found: true, count: 9659365, prefix: '5BAA6', … } — only '5BAA6' was sent
```

---

## Why it exists

This started as a rewrite of a password page whose tools were quietly wrong in ways that are common
across the web:

| Common problem | What this library does |
|---|---|
| A strength meter that multiplies length by character-set size, so `P@ssw0rd!x` looks strong | Treats that figure as a *ceiling*, then models what cracking tools actually try: common passwords, word + suffix, leet substitutions, years, keyboard runs, sequences, repeats, tiny alphabets |
| "Memorable password" generators using `Math.random()` and a tiny word list, while the meter reports ~90 bits | All randomness from `crypto.getRandomValues`, with **rejection sampling** so there is no modulo bias; the generator reports the *real* entropy of how the password was made |
| Passphrases from a small or unlicensed list | The **EFF Large Wordlist** — 7,776 words, 12.9 bits each, the same list designed for rolling five dice |
| Breach checks that send your password (or its full hash) somewhere | k-anonymity: only the first 5 characters of the SHA-1 hash leave the machine, with response padding requested |

Two estimator bugs were found while writing this repo's tests and fixed in the live tool too: random
strings containing symbols were being split into "words" and scored as a weak passphrase, and all-digit
PINs were being "de-leeted" into fake letters and scored as a pronounceable word.

---

## API

| Function | Returns |
|---|---|
| `estimate(password)` | `{ bits, ceiling, verdict, notes[] }` — verdict: `terrible` <28 · `weak` <40 · `fair` <60 · `strong` <80 · `excellent` |
| `crackTimes(bits)` | `{ fast, slow }` — plain-English time at 10¹¹ guesses/s (fast hash, GPUs) and 10⁴/s (bcrypt/argon2) |
| `generatePassword(length, { upper, lower, digits, symbols, noAmbiguous })` | `{ password, bits, pool }`, or `null` if no character classes |
| `generatePassphrase(words, separator, capitalise, addNumber)` | `{ password, bits, words }` |
| `checkBreach(password, { fetch })` | `{ found, count, prefix, returned }` — throws if the API is unreachable |
| `sha1Hex(string)` | Upper-case hex SHA-1 (Web Crypto) |
| `randInt(max)` | Unbiased integer in `[0, max)` |
| `WORDS` | The EFF wordlist array |

---

## What it can't tell you

- **Whether a password you chose is random.** The estimator can spot the patterns people use, but a
  human-chosen password that avoids them all still gets the benefit of the doubt. The generators are the
  way to get a password whose strength is actually known.
- **Every dictionary.** It carries a short list of the most common passwords and the EFF wordlist, not the
  multi-gigabyte lists attackers use — names and rarer words fall back to a "pronounceable" heuristic.
- **Whether a password is safe because it isn't in HIBP.** Not being in a breach corpus is necessary, not
  sufficient.

---

## Tests

```
node tests/run.js
```

- The wordlist is byte-for-byte the EFF file, in order (`tests/eff_large_wordlist.txt`)
- `randInt` range, plus a chi-square uniformity check over 60,000 draws
- Generator entropy figures, character pools, no-ambiguous-characters mode
- Estimator verdicts for common passwords, leet words, word + suffix, keyboard runs, digits-only, repeats,
  random strings and passphrases — including regressions for the two bugs above
- SHA-1 against FIPS 180 test vectors, and the breach check against a fake API: only the 5-character
  prefix is requested, padding lines are ignored, API errors surface

CI runs on Node 18, 20 and 22.

---

## Licence

Code: **MIT** — see [LICENSE](LICENSE).

Wordlist (`eff-wordlist.js`, `tests/eff_large_wordlist.txt`): the
[EFF Large Wordlist for Passphrases](https://www.eff.org/dice) by the **Electronic Frontier Foundation**,
licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/). Unmodified apart from
dropping the dice numbers in the JS module.

Built by [ExamineIP](https://examineip.com/). Try it in the browser at
[Password Tools](https://tools.examineip.com/password-tools/) — nothing you type leaves the page except
the 5-character hash prefix for the breach check.
