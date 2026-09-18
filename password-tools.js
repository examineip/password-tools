/*!
 * password-tools — honest password strength estimates, cryptographically random
 * generators, and a private Have I Been Pwned check (k-anonymity).
 *
 * Browser and Node 18+. No dependencies; the passphrase generator uses the
 * EFF Large Wordlist (eff-wordlist.js, CC BY 3.0 US).
 * MIT License — https://github.com/examineip/password-tools
 */
(function (root, factory) {
  if (typeof module === 'object' ? module.exports : false) module.exports = factory(require('./eff-wordlist.js'));
  else root.passwordTools = factory(root.EFF_WORDLIST);
})(typeof self !== 'undefined' ? self : this, function (wordlist) {
  'use strict';

  var WORDS = wordlist;
  // Web Crypto: global in browsers and Node 19+, under require('crypto').webcrypto in Node 18.
  var crypto = (typeof globalThis !== 'undefined' ? globalThis.crypto : undefined) ||
    (typeof require === 'function' ? require('crypto').webcrypto : undefined);

  /* ------------------------------------------------------------------ *
   * Random
   * ------------------------------------------------------------------ */

  function randInt(max) {
    // Uniform integer in [0, max). Rejection sampling removes the bias that
    // a plain "random % max" introduces when max does not divide 2^32.
    if (max <= 0) return 0;
    var limit = Math.floor(4294967296 / max) * max;
    var buf = new Uint32Array(1);
    var v;
    do {
      crypto.getRandomValues(buf);
      v = buf[0];
    } while (v >= limit);
    return v % max;
  }

  function pick(arr) {
    return arr[randInt(arr.length)];
  }

  /* ------------------------------------------------------------------ *
   * Strength estimation
   *
   * Character-set entropy (length x log2(pool)) is the number every weak
   * strength meter shows. It answers "how many passwords of this shape exist",
   * which is the right question only if the password was generated at random.
   * A human-chosen password is not, so we treat that figure as a ceiling and
   * look for the patterns real cracking tools exploit.
   * ------------------------------------------------------------------ */

  var COMMON = ['123456','password','123456789','12345678','12345','qwerty','1234567','111111','1234567890',
    '123123','abc123','1234','password1','iloveyou','000000','qwerty123','monkey','dragon','letmein','sunshine',
    'princess','admin','welcome','login','master','football','baseball','shadow','superman','trustno1','batman',
    'passw0rd','starwars','whatever','qazwsx','michael','jennifer','hunter','freedom','ninja','mustang','access',
    'flower','hottie','loveme','zaq1zaq1','password123','charlie','donald','qwertyuiop','asdfghjkl','zxcvbnm',
    'p@ssw0rd','secret','summer','winter','soccer','hockey','killer','george','sexy','andrew','charlie','thomas',
    'robert','daniel','harley','ranger','buster','tigger','jordan','jessica','pepper','111222','654321','121212'];

  var KEYBOARD = ['qwertyuiop','asdfghjkl','zxcvbnm','1234567890','qwerty','asdfgh','zxcvbn','qazwsx','wsxedc'];

  function deLeet(s) {
    return s.toLowerCase()
      .replace(/[4@]/g, 'a').replace(/3/g, 'e').replace(/[1!|]/g, 'i')
      .replace(/0/g, 'o').replace(/[5$]/g, 's').replace(/7/g, 't').replace(/8/g, 'b');
  }

  /* Does a run of letters look like a word someone could say?
   * Real words have vowels spread through them; random letters do not. This is
   * how "Tr0ub4dor" gets treated as a word rather than as nine random letters,
   * without needing a full English dictionary in the page. It is deliberately
   * conservative: anything it is unsure about is scored as random, which errs
   * toward flattering the password rather than alarming the user wrongly. */
  function isPronounceable(letters) {
    var s = letters.toLowerCase();
    if (s.length < 5) return false;
    var vowels = s.replace(/[^aeiouy]/g, '').length;
    var ratio = vowels / s.length;
    if (ratio < 0.2) return false;
    if (ratio > 0.6) return false;
    if (/[^aeiouy]{4,}/.test(s)) return false;   // no real word runs 4 consonants
    return true;
  }

  function poolSize(pw) {
    var pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^A-Za-z0-9]/.test(pw)) pool += 33;
    return pool;
  }

  function estimate(pw) {
    var notes = [];
    if (!pw) return { bits: 0, ceiling: 0, notes: [], verdict: 'empty' };

    var pool = poolSize(pw);
    var ceiling = pw.length * Math.log2(pool || 1);
    var bits = ceiling;

    var lower = pw.toLowerCase();
    var flat = deLeet(pw);

    // 1. Exact match against the passwords attackers try first.
    if (COMMON.indexOf(lower) !== -1 || COMMON.indexOf(flat) !== -1) {
      notes.push('This is one of the most commonly used passwords in the world. It is guessed within seconds.');
      return { bits: 4, ceiling: ceiling, notes: notes, verdict: 'terrible' };
    }

    // 2. Is it a passphrase? Three or more word-like tokens are best modelled as
    //    word picks, not as characters. 13 bits per word approximates an attacker
    //    working from a list of a few thousand common English words.
    var tokens = flat.split(/[^a-z]+/).filter(function (t) { return t.length >= 3; });
    var nonWordChars = pw.replace(/[A-Za-z]/g, '').length;
    /* Only count tokens that are plausibly words. Splitting a random string on
     * its symbols also yields letter runs ("qlx", "mzp"), and scoring those as
     * dictionary words badly underrated random passwords (fixed 18 Sept 2026). */
    var wordish = tokens.filter(function (t) {
      if (typeof WORDS !== 'undefined' ? WORDS.indexOf(t) !== -1 : false) return true;
      if (t.length < 5) return /[aeiouy]/.test(t) ? !/[^aeiouy]{3,}/.test(t) : false;
      return isPronounceable(t);
    });
    var wordLetters = wordish.join('').length;
    var allLetters = flat.replace(/[^a-z]/g, '').length;
    if (wordish.length >= 3 ? wordLetters >= allLetters * 0.7 : false) {
      tokens = wordish;
      var wordBits = tokens.length * 13 + Math.min(nonWordChars, 6) * 2;
      if (wordBits < bits) {
        bits = wordBits;
        notes.push('Read as a passphrase: ' + tokens.length + ' words. Strength comes from how many words ' +
                   'there are and how randomly they were chosen, not from the character count.');
      }
    } else {
      // 3. A single word core with digits or symbols attached - the most common
      //    human pattern, and one every cracking ruleset covers.
      var m = pw.match(/^([A-Za-z]+)([^A-Za-z]{1,6})$/);
      if (m) {
        var core = deLeet(m[1]);
        var suffixBits = Math.min(m[2].length, 4) * 3.3;
        if (COMMON.indexOf(core) !== -1) {
          bits = Math.min(bits, 10 + suffixBits);
          notes.push('A very common password with characters added to the end. Cracking rules try exactly this.');
        } else if (typeof WORDS !== 'undefined' && WORDS.indexOf(core) !== -1) {
          bits = Math.min(bits, Math.log2(WORDS.length) + suffixBits);
          notes.push('A dictionary word with characters added to the end. Attackers apply that rule to every ' +
                     'word in the list, so the additions buy much less than they appear to.');
        } else if (isPronounceable(m[1])) {
          bits = Math.min(bits, 15 + suffixBits);
          notes.push('A pronounceable word or name with digits or symbols on the end. Our dictionary does not ' +
                     'hold this particular word, but an attacker’s does — that shape is the first thing they try.');
        } else {
          // Not in any list we hold, but still letters-then-suffix: give it the
          // letter-space value rather than the full mixed-character ceiling.
          var letterPool = /[A-Z]/.test(m[1]) ? 52 : 26;
          bits = Math.min(bits, m[1].length * Math.log2(letterPool) + suffixBits);
          notes.push('Letters followed by digits or symbols. That shape is predictable even when the word is not ' +
                     'in a dictionary, so the realistic strength sits below the theoretical figure.');
        }
      } else {
        // No clean word-then-suffix split, but the letters on their own may still
        // spell something - this is the "Tr0ub4dor&3" case, where the digits sit
        // inside the word rather than after it.
        var letters = flat.replace(/[^a-z]/g, '');
        var extras = pw.length - letters.length;
        /* Only when most of that "word" is real letters: an all-digit PIN de-leets
         * into fake letters (4->a, 7->t ...) that can look pronounceable. */
        var realLetters = pw.replace(/[^A-Za-z]/g, '').length;
        if (pw.length <= 16 && realLetters * 2 >= letters.length && isPronounceable(letters)) {
          bits = Math.min(bits, 15 + Math.min(extras, 5) * 3);
          notes.push('Under the digits and symbols this is a pronounceable word. Substituting 0 for o, 4 for a ' +
                     'and so on is built into every cracking tool, so those swaps add far less than they look.');
        }
      }
    }

    // 4. Cheap patterns, applied on top.
    if (/(19|20)\d{2}/.test(pw)) {
      notes.push('It contains something that looks like a year — among the first substitutions a cracking rule makes.');
      bits = bits - 6;
    }
    for (var k = 0; k < KEYBOARD.length; k++) {
      if (flat.indexOf(KEYBOARD[k].slice(0, 5)) !== -1) {
        notes.push('It contains a run of adjacent keyboard keys.');
        bits = bits - 10;
        break;
      }
    }
    if (/(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|678|789)/i.test(pw)) {
      notes.push('It contains a sequence like 123 or abc.');
      bits = bits - 6;
    }
    if (/(.)\1{2,}/.test(pw)) {
      notes.push('It repeats the same character three or more times in a row.');
      bits = bits - 4;
    }
    if (/^[0-9]+$/.test(pw)) {
      notes.push('Digits only — the search space is small however long it is.');
      bits = Math.min(bits, pw.length * Math.log2(10));
    }

    // Very few distinct characters. Length counts for nothing if the alphabet
    // actually used is two symbols: "aaaaaaaaaaaa" is one guess, not twelve
    // characters' worth. Cost = choosing which symbols, plus arranging them.
    var seen = {};
    for (var u = 0; u < pw.length; u++) seen[pw.charAt(u)] = 1;
    var distinct = Object.keys(seen).length;
    if (distinct <= 6 && distinct < pw.length) {
      var limited = pw.length * Math.log2(distinct) + distinct * Math.log2(pool || 1);
      if (limited < bits) {
        bits = limited;
        notes.push('Only ' + distinct + ' distinct character' + (distinct === 1 ? '' : 's') +
                   ' in the whole password. Length stops helping once the alphabet is that small.');
      }
    }
    if (pw.length < 8) {
      notes.push('Under 8 characters is short enough to brute-force whatever it contains.');
      bits = Math.min(bits, ceiling);
    }

    bits = Math.max(0, bits);

    var verdict;
    if (bits < 28) verdict = 'terrible';
    else if (bits < 40) verdict = 'weak';
    else if (bits < 60) verdict = 'fair';
    else if (bits < 80) verdict = 'strong';
    else verdict = 'excellent';

    if (!notes.length) {
      notes.push('No common patterns found. The estimate assumes an attacker has to search the whole space, ' +
                 'which holds only if you did not choose this password by hand.');
    }
    return { bits: bits, ceiling: ceiling, notes: notes, verdict: verdict };
  }

  /* Two honest scenarios rather than one invented number. */
  function crackTimes(bits) {
    var guesses = Math.pow(2, bits) / 2;
    return {
      fast: humanTime(guesses / 1e11),   // offline attack on a fast hash (MD5/SHA-1) with GPUs
      slow: humanTime(guesses / 1e4)     // a site that stores passwords properly (bcrypt/argon2)
    };
  }

  function humanTime(seconds) {
    if (!isFinite(seconds)) return 'longer than the universe has existed';
    if (seconds < 1) return 'instantly';
    var steps = [
      [1, 'second', 'seconds'],
      [60, 'minute', 'minutes'],
      [3600, 'hour', 'hours'],
      [86400, 'day', 'days'],
      [31557600, 'year', 'years'],
      [3155760000, 'century', 'centuries']
    ];
    var chosen = steps[0];
    for (var i = 0; i < steps.length; i++) {
      if (seconds >= steps[i][0]) chosen = steps[i];
    }
    var v = seconds / chosen[0];
    if (v > 1e6) return 'effectively forever';
    var num = v < 10 ? Math.round(v * 10) / 10 : Math.round(v);
    return 'about ' + num.toLocaleString('en-US') + ' ' + (num === 1 ? chosen[1] : chosen[2]);
  }

  /* ------------------------------------------------------------------ *
   * Generators
   * ------------------------------------------------------------------ */

  function generatePassword(len, opts) {
    var chars = '';
    if (opts.upper)  chars += opts.noAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (opts.lower)  chars += opts.noAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
    if (opts.digits) chars += opts.noAmbiguous ? '23456789' : '0123456789';
    if (opts.symbols) chars += '!@#$%^*()-_=+[]{};:,.?';
    if (!chars) return null;

    var out = '';
    for (var i = 0; i < len; i++) out += chars.charAt(randInt(chars.length));
    return { password: out, bits: len * Math.log2(chars.length), pool: chars.length };
  }

  function generatePassphrase(count, sep, capitalise, addNumber) {
    var parts = [];
    for (var i = 0; i < count; i++) {
      var w = WORDS[randInt(WORDS.length)];
      parts.push(capitalise ? w.charAt(0).toUpperCase() + w.slice(1) : w);
    }
    var bits = count * Math.log2(WORDS.length);
    var phrase = parts.join(sep);
    if (addNumber) {
      phrase += sep + randInt(100);       // crypto random, not Math.random
      bits += Math.log2(100);
    }
    return { password: phrase, bits: bits, words: count };
  }

  /* ------------------------------------------------------------------ *
   * Breach check — k-anonymity
   *
   * The password is hashed locally with SHA-1. Only the first five characters
   * of that hash are sent. The API returns every suffix sharing that prefix -
   * around 800 of them - and the comparison happens here. The service never
   * learns the password, and never even learns the full hash.
   * ------------------------------------------------------------------ */

  async function sha1Hex(str) {
    var buf = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf))
      .map(function (b) { return b.toString(16).padStart(2, '0'); })
      .join('')
      .toUpperCase();
  }

  async function checkBreach(password, opts) {
    opts = opts || {};
    var f = opts.fetch || (typeof fetch === 'function' ? fetch : null);
    if (!f) throw new Error('No fetch available');
    var hash = await sha1Hex(password);
    var prefix = hash.slice(0, 5);
    var suffix = hash.slice(5);

    var res = await f('https://api.pwnedpasswords.com/range/' + prefix, {
      headers: { 'Add-Padding': 'true' }
    });
    if (!res.ok) throw new Error('lookup failed');

    var body = await res.text();
    var lines = body.split('\n');
    for (var i = 0; i < lines.length; i++) {
      var parts = lines[i].trim().split(':');
      if (parts[0] === suffix) {
        var n = parseInt(parts[1], 10);
        if (n > 0) return { found: true, count: n, prefix: prefix, returned: lines.length };
      }
    }
    return { found: false, count: 0, prefix: prefix, returned: lines.length };
  }

  return {
    WORDS: WORDS,
    randInt: randInt,
    pick: pick,
    estimate: estimate,
    crackTimes: crackTimes,
    humanTime: humanTime,
    generatePassword: generatePassword,
    generatePassphrase: generatePassphrase,
    sha1Hex: sha1Hex,
    checkBreach: checkBreach
  };
});
