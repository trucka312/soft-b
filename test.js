/*
 CryptoJS v3.1.2
 code.google.com/p/crypto-js
 (c) 2009-2013 by Jeff Mott. All rights reserved.
 code.google.com/p/crypto-js/wiki/License
*/
var com_sbps_system = com_sbps_system || {};
(function (L) {
  var b = L.CryptoJS,
    b =
      b ||
      (function (b, c) {
        var r = {},
          m = (r.lib = {}),
          y = function () {},
          A = (m.Base = {
            extend: function (d) {
              y.prototype = this;
              var b = new y();
              d && b.mixIn(d);
              b.hasOwnProperty("init") ||
                (b.init = function () {
                  b.$super.init.apply(this, arguments);
                });
              b.init.prototype = b;
              b.$super = this;
              return b;
            },
            create: function () {
              var d = this.extend();
              d.init.apply(d, arguments);
              return d;
            },
            init: function () {},
            mixIn: function (d) {
              for (var b in d) d.hasOwnProperty(b) && (this[b] = d[b]);
              d.hasOwnProperty("toString") && (this.toString = d.toString);
            },
            clone: function () {
              return this.init.prototype.extend(this);
            },
          }),
          z = (m.WordArray = A.extend({
            init: function (d, b) {
              d = this.words = d || [];
              this.sigBytes = b != c ? b : 4 * d.length;
            },
            toString: function (d) {
              return (d || D).stringify(this);
            },
            concat: function (d) {
              var b = this.words,
                t = d.words,
                p = this.sigBytes;
              d = d.sigBytes;
              this.clamp();
              if (p % 4)
                for (var B = 0; B < d; B++)
                  b[(p + B) >>> 2] |=
                    ((t[B >>> 2] >>> (24 - (B % 4) * 8)) & 255) <<
                    (24 - ((p + B) % 4) * 8);
              else if (65535 < t.length)
                for (B = 0; B < d; B += 4) b[(p + B) >>> 2] = t[B >>> 2];
              else b.push.apply(b, t);
              this.sigBytes += d;
              return this;
            },
            clamp: function () {
              var d = this.words,
                n = this.sigBytes;
              d[n >>> 2] &= 4294967295 << (32 - (n % 4) * 8);
              d.length = b.ceil(n / 4);
            },
            clone: function () {
              var d = A.clone.call(this);
              d.words = this.words.slice(0);
              return d;
            },
            random: function (d) {
              for (var n = [], t = 0; t < d; t += 4)
                n.push((4294967296 * b.random()) | 0);
              return new z.init(n, d);
            },
          })),
          C = (r.enc = {}),
          D = (C.Hex = {
            stringify: function (d) {
              var b = d.words;
              d = d.sigBytes;
              for (var t = [], p = 0; p < d; p++) {
                var B = (b[p >>> 2] >>> (24 - (p % 4) * 8)) & 255;
                t.push((B >>> 4).toString(16));
                t.push((B & 15).toString(16));
              }
              return t.join("");
            },
            parse: function (d) {
              for (var b = d.length, t = [], p = 0; p < b; p += 2)
                t[p >>> 3] |=
                  parseInt(d.substr(p, 2), 16) << (24 - (p % 8) * 4);
              return new z.init(t, b / 2);
            },
          }),
          f = (C.Latin1 = {
            stringify: function (d) {
              var b = d.words;
              d = d.sigBytes;
              for (var t = [], p = 0; p < d; p++)
                t.push(
                  String.fromCharCode((b[p >>> 2] >>> (24 - (p % 4) * 8)) & 255)
                );
              return t.join("");
            },
            parse: function (d) {
              for (var b = d.length, t = [], p = 0; p < b; p++)
                t[p >>> 2] |= (d.charCodeAt(p) & 255) << (24 - (p % 4) * 8);
              return new z.init(t, b);
            },
          }),
          F = (C.Utf8 = {
            stringify: function (d) {
              try {
                return decodeURIComponent(escape(f.stringify(d)));
              } catch (b) {
                throw Error("Malformed UTF-8 data");
              }
            },
            parse: function (d) {
              return f.parse(unescape(encodeURIComponent(d)));
            },
          }),
          G = (m.BufferedBlockAlgorithm = A.extend({
            reset: function () {
              this._data = new z.init();
              this._nDataBytes = 0;
            },
            _append: function (d) {
              "string" == typeof d && (d = F.parse(d));
              this._data.concat(d);
              this._nDataBytes += d.sigBytes;
            },
            _process: function (d) {
              var n = this._data,
                t = n.words,
                p = n.sigBytes,
                B = this.blockSize,
                c = p / (4 * B),
                c = d ? b.ceil(c) : b.max((c | 0) - this._minBufferSize, 0);
              d = c * B;
              p = b.min(4 * d, p);
              if (d) {
                for (var f = 0; f < d; f += B) this._doProcessBlock(t, f);
                f = t.splice(0, d);
                n.sigBytes -= p;
              }
              return new z.init(f, p);
            },
            clone: function () {
              var d = A.clone.call(this);
              d._data = this._data.clone();
              return d;
            },
            _minBufferSize: 0,
          }));
        m.Hasher = G.extend({
          cfg: A.extend(),
          init: function (d) {
            this.cfg = this.cfg.extend(d);
            this.reset();
          },
          reset: function () {
            G.reset.call(this);
            this._doReset();
          },
          update: function (d) {
            this._append(d);
            this._process();
            return this;
          },
          finalize: function (d) {
            d && this._append(d);
            return this._doFinalize();
          },
          blockSize: 16,
          _createHelper: function (d) {
            return function (b, t) {
              return new d.init(t).finalize(b);
            };
          },
          _createHmacHelper: function (d) {
            return function (b, t) {
              return new I.HMAC.init(d, t).finalize(b);
            };
          },
        });
        var I = (r.algo = {});
        return r;
      })(Math);
  (function () {
    var h = b,
      c = h.lib.WordArray;
    h.enc.Base64 = {
      stringify: function (b) {
        var c = b.words,
          h = b.sigBytes,
          A = this._map;
        b.clamp();
        b = [];
        for (var z = 0; z < h; z += 3)
          for (
            var C =
                (((c[z >>> 2] >>> (24 - (z % 4) * 8)) & 255) << 16) |
                (((c[(z + 1) >>> 2] >>> (24 - ((z + 1) % 4) * 8)) & 255) << 8) |
                ((c[(z + 2) >>> 2] >>> (24 - ((z + 2) % 4) * 8)) & 255),
              D = 0;
            4 > D && z + 0.75 * D < h;
            D++
          )
            b.push(A.charAt((C >>> (6 * (3 - D))) & 63));
        if ((c = A.charAt(64))) for (; b.length % 4; ) b.push(c);
        return b.join("");
      },
      parse: function (b) {
        var m = b.length,
          h = this._map,
          A = h.charAt(64);
        A && ((A = b.indexOf(A)), -1 != A && (m = A));
        for (var A = [], z = 0, C = 0; C < m; C++)
          if (C % 4) {
            var D = h.indexOf(b.charAt(C - 1)) << ((C % 4) * 2),
              f = h.indexOf(b.charAt(C)) >>> (6 - (C % 4) * 2);
            A[z >>> 2] |= (D | f) << (24 - (z % 4) * 8);
            z++;
          }
        return c.create(A, z);
      },
      _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    };
  })();
  (function (h) {
    function c(b, c, d, n, t, p, B) {
      b = b + ((c & d) | (~c & n)) + t + B;
      return ((b << p) | (b >>> (32 - p))) + c;
    }
    function r(b, c, d, n, t, p, B) {
      b = b + ((c & n) | (d & ~n)) + t + B;
      return ((b << p) | (b >>> (32 - p))) + c;
    }
    function m(b, c, d, n, t, p, B) {
      b = b + (c ^ d ^ n) + t + B;
      return ((b << p) | (b >>> (32 - p))) + c;
    }
    function y(b, c, d, n, t, p, B) {
      b = b + (d ^ (c | ~n)) + t + B;
      return ((b << p) | (b >>> (32 - p))) + c;
    }
    for (
      var A = b,
        z = A.lib,
        C = z.WordArray,
        D = z.Hasher,
        z = A.algo,
        f = [],
        F = 0;
      64 > F;
      F++
    )
      f[F] = (4294967296 * h.abs(h.sin(F + 1))) | 0;
    z = z.MD5 = D.extend({
      _doReset: function () {
        this._hash = new C.init([
          1732584193, 4023233417, 2562383102, 271733878,
        ]);
      },
      _doProcessBlock: function (b, h) {
        for (var d = 0; 16 > d; d++) {
          var n = h + d,
            t = b[n];
          b[n] =
            (((t << 8) | (t >>> 24)) & 16711935) |
            (((t << 24) | (t >>> 8)) & 4278255360);
        }
        var d = this._hash.words,
          n = b[h + 0],
          t = b[h + 1],
          p = b[h + 2],
          B = b[h + 3],
          E = b[h + 4],
          z = b[h + 5],
          C = b[h + 6],
          A = b[h + 7],
          D = b[h + 8],
          F = b[h + 9],
          K = b[h + 10],
          N = b[h + 11],
          S = b[h + 12],
          Q = b[h + 13],
          P = b[h + 14],
          O = b[h + 15],
          u = d[0],
          k = d[1],
          w = d[2],
          x = d[3],
          u = c(u, k, w, x, n, 7, f[0]),
          x = c(x, u, k, w, t, 12, f[1]),
          w = c(w, x, u, k, p, 17, f[2]),
          k = c(k, w, x, u, B, 22, f[3]),
          u = c(u, k, w, x, E, 7, f[4]),
          x = c(x, u, k, w, z, 12, f[5]),
          w = c(w, x, u, k, C, 17, f[6]),
          k = c(k, w, x, u, A, 22, f[7]),
          u = c(u, k, w, x, D, 7, f[8]),
          x = c(x, u, k, w, F, 12, f[9]),
          w = c(w, x, u, k, K, 17, f[10]),
          k = c(k, w, x, u, N, 22, f[11]),
          u = c(u, k, w, x, S, 7, f[12]),
          x = c(x, u, k, w, Q, 12, f[13]),
          w = c(w, x, u, k, P, 17, f[14]),
          k = c(k, w, x, u, O, 22, f[15]),
          u = r(u, k, w, x, t, 5, f[16]),
          x = r(x, u, k, w, C, 9, f[17]),
          w = r(w, x, u, k, N, 14, f[18]),
          k = r(k, w, x, u, n, 20, f[19]),
          u = r(u, k, w, x, z, 5, f[20]),
          x = r(x, u, k, w, K, 9, f[21]),
          w = r(w, x, u, k, O, 14, f[22]),
          k = r(k, w, x, u, E, 20, f[23]),
          u = r(u, k, w, x, F, 5, f[24]),
          x = r(x, u, k, w, P, 9, f[25]),
          w = r(w, x, u, k, B, 14, f[26]),
          k = r(k, w, x, u, D, 20, f[27]),
          u = r(u, k, w, x, Q, 5, f[28]),
          x = r(x, u, k, w, p, 9, f[29]),
          w = r(w, x, u, k, A, 14, f[30]),
          k = r(k, w, x, u, S, 20, f[31]),
          u = m(u, k, w, x, z, 4, f[32]),
          x = m(x, u, k, w, D, 11, f[33]),
          w = m(w, x, u, k, N, 16, f[34]),
          k = m(k, w, x, u, P, 23, f[35]),
          u = m(u, k, w, x, t, 4, f[36]),
          x = m(x, u, k, w, E, 11, f[37]),
          w = m(w, x, u, k, A, 16, f[38]),
          k = m(k, w, x, u, K, 23, f[39]),
          u = m(u, k, w, x, Q, 4, f[40]),
          x = m(x, u, k, w, n, 11, f[41]),
          w = m(w, x, u, k, B, 16, f[42]),
          k = m(k, w, x, u, C, 23, f[43]),
          u = m(u, k, w, x, F, 4, f[44]),
          x = m(x, u, k, w, S, 11, f[45]),
          w = m(w, x, u, k, O, 16, f[46]),
          k = m(k, w, x, u, p, 23, f[47]),
          u = y(u, k, w, x, n, 6, f[48]),
          x = y(x, u, k, w, A, 10, f[49]),
          w = y(w, x, u, k, P, 15, f[50]),
          k = y(k, w, x, u, z, 21, f[51]),
          u = y(u, k, w, x, S, 6, f[52]),
          x = y(x, u, k, w, B, 10, f[53]),
          w = y(w, x, u, k, K, 15, f[54]),
          k = y(k, w, x, u, t, 21, f[55]),
          u = y(u, k, w, x, D, 6, f[56]),
          x = y(x, u, k, w, O, 10, f[57]),
          w = y(w, x, u, k, C, 15, f[58]),
          k = y(k, w, x, u, Q, 21, f[59]),
          u = y(u, k, w, x, E, 6, f[60]),
          x = y(x, u, k, w, N, 10, f[61]),
          w = y(w, x, u, k, p, 15, f[62]),
          k = y(k, w, x, u, F, 21, f[63]);
        d[0] = (d[0] + u) | 0;
        d[1] = (d[1] + k) | 0;
        d[2] = (d[2] + w) | 0;
        d[3] = (d[3] + x) | 0;
      },
      _doFinalize: function () {
        var b = this._data,
          c = b.words,
          d = 8 * this._nDataBytes,
          n = 8 * b.sigBytes;
        c[n >>> 5] |= 128 << (24 - (n % 32));
        var t = h.floor(d / 4294967296);
        c[(((n + 64) >>> 9) << 4) + 15] =
          (((t << 8) | (t >>> 24)) & 16711935) |
          (((t << 24) | (t >>> 8)) & 4278255360);
        c[(((n + 64) >>> 9) << 4) + 14] =
          (((d << 8) | (d >>> 24)) & 16711935) |
          (((d << 24) | (d >>> 8)) & 4278255360);
        b.sigBytes = 4 * (c.length + 1);
        this._process();
        b = this._hash;
        c = b.words;
        for (d = 0; 4 > d; d++)
          (n = c[d]),
            (c[d] =
              (((n << 8) | (n >>> 24)) & 16711935) |
              (((n << 24) | (n >>> 8)) & 4278255360));
        return b;
      },
      clone: function () {
        var b = D.clone.call(this);
        b._hash = this._hash.clone();
        return b;
      },
    });
    A.MD5 = D._createHelper(z);
    A.HmacMD5 = D._createHmacHelper(z);
  })(Math);
  (function () {
    var h = b,
      c = h.lib,
      r = c.Base,
      m = c.WordArray,
      c = h.algo,
      y = (c.EvpKDF = r.extend({
        cfg: r.extend({ keySize: 4, hasher: c.MD5, iterations: 1 }),
        init: function (b) {
          this.cfg = this.cfg.extend(b);
        },
        compute: function (b, c) {
          for (
            var h = this.cfg,
              r = h.hasher.create(),
              f = m.create(),
              y = f.words,
              G = h.keySize,
              h = h.iterations;
            y.length < G;

          ) {
            I && r.update(I);
            var I = r.update(b).finalize(c);
            r.reset();
            for (var d = 1; d < h; d++) (I = r.finalize(I)), r.reset();
            f.concat(I);
          }
          f.sigBytes = 4 * G;
          return f;
        },
      }));
    h.EvpKDF = function (b, c, h) {
      return y.create(h).compute(b, c);
    };
  })();
  b.lib.Cipher ||
    (function (h) {
      var c = b,
        r = c.lib,
        m = r.Base,
        y = r.WordArray,
        A = r.BufferedBlockAlgorithm,
        z = c.enc.Base64,
        C = c.algo.EvpKDF,
        D = (r.Cipher = A.extend({
          cfg: m.extend(),
          createEncryptor: function (b, d) {
            return this.create(this._ENC_XFORM_MODE, b, d);
          },
          createDecryptor: function (b, d) {
            return this.create(this._DEC_XFORM_MODE, b, d);
          },
          init: function (b, d, c) {
            this.cfg = this.cfg.extend(c);
            this._xformMode = b;
            this._key = d;
            this.reset();
          },
          reset: function () {
            A.reset.call(this);
            this._doReset();
          },
          process: function (b) {
            this._append(b);
            return this._process();
          },
          finalize: function (b) {
            b && this._append(b);
            return this._doFinalize();
          },
          keySize: 4,
          ivSize: 4,
          _ENC_XFORM_MODE: 1,
          _DEC_XFORM_MODE: 2,
          _createHelper: function (b) {
            return {
              encrypt: function (p, c, f) {
                return ("string" == typeof c ? n : d).encrypt(b, p, c, f);
              },
              decrypt: function (p, c, f) {
                return ("string" == typeof c ? n : d).decrypt(b, p, c, f);
              },
            };
          },
        }));
      r.StreamCipher = D.extend({
        _doFinalize: function () {
          return this._process(!0);
        },
        blockSize: 1,
      });
      var f = (c.mode = {}),
        F = function (b, d, c) {
          var n = this._iv;
          n ? (this._iv = h) : (n = this._prevBlock);
          for (var f = 0; f < c; f++) b[d + f] ^= n[f];
        },
        G = (r.BlockCipherMode = m.extend({
          createEncryptor: function (b, d) {
            return this.Encryptor.create(b, d);
          },
          createDecryptor: function (b, d) {
            return this.Decryptor.create(b, d);
          },
          init: function (b, d) {
            this._cipher = b;
            this._iv = d;
          },
        })).extend();
      G.Encryptor = G.extend({
        processBlock: function (b, d) {
          var c = this._cipher,
            f = c.blockSize;
          F.call(this, b, d, f);
          c.encryptBlock(b, d);
          this._prevBlock = b.slice(d, d + f);
        },
      });
      G.Decryptor = G.extend({
        processBlock: function (b, d) {
          var c = this._cipher,
            f = c.blockSize,
            n = b.slice(d, d + f);
          c.decryptBlock(b, d);
          F.call(this, b, d, f);
          this._prevBlock = n;
        },
      });
      f = f.CBC = G;
      G = (c.pad = {}).Pkcs7 = {
        pad: function (b, d) {
          for (
            var c = 4 * d,
              c = c - (b.sigBytes % c),
              f = (c << 24) | (c << 16) | (c << 8) | c,
              n = [],
              h = 0;
            h < c;
            h += 4
          )
            n.push(f);
          c = y.create(n, c);
          b.concat(c);
        },
        unpad: function (b) {
          b.sigBytes -= b.words[(b.sigBytes - 1) >>> 2] & 255;
        },
      };
      r.BlockCipher = D.extend({
        cfg: D.cfg.extend({ mode: f, padding: G }),
        reset: function () {
          D.reset.call(this);
          var b = this.cfg,
            d = b.iv,
            b = b.mode;
          if (this._xformMode == this._ENC_XFORM_MODE)
            var c = b.createEncryptor;
          else (c = b.createDecryptor), (this._minBufferSize = 1);
          this._mode = c.call(b, this, d && d.words);
        },
        _doProcessBlock: function (b, d) {
          this._mode.processBlock(b, d);
        },
        _doFinalize: function () {
          var b = this.cfg.padding;
          if (this._xformMode == this._ENC_XFORM_MODE) {
            b.pad(this._data, this.blockSize);
            var d = this._process(!0);
          } else (d = this._process(!0)), b.unpad(d);
          return d;
        },
        blockSize: 4,
      });
      var I = (r.CipherParams = m.extend({
          init: function (b) {
            this.mixIn(b);
          },
          toString: function (b) {
            return (b || this.formatter).stringify(this);
          },
        })),
        f = ((c.format = {}).OpenSSL = {
          stringify: function (b) {
            var d = b.ciphertext;
            b = b.salt;
            return (
              b ? y.create([1398893684, 1701076831]).concat(b).concat(d) : d
            ).toString(z);
          },
          parse: function (b) {
            b = z.parse(b);
            var d = b.words;
            if (1398893684 == d[0] && 1701076831 == d[1]) {
              var c = y.create(d.slice(2, 4));
              d.splice(0, 4);
              b.sigBytes -= 16;
            }
            return I.create({ ciphertext: b, salt: c });
          },
        }),
        d = (r.SerializableCipher = m.extend({
          cfg: m.extend({ format: f }),
          encrypt: function (b, d, c, f) {
            f = this.cfg.extend(f);
            var n = b.createEncryptor(c, f);
            d = n.finalize(d);
            n = n.cfg;
            return I.create({
              ciphertext: d,
              key: c,
              iv: n.iv,
              algorithm: b,
              mode: n.mode,
              padding: n.padding,
              blockSize: b.blockSize,
              formatter: f.format,
            });
          },
          decrypt: function (b, d, c, f) {
            f = this.cfg.extend(f);
            d = this._parse(d, f.format);
            return b.createDecryptor(c, f).finalize(d.ciphertext);
          },
          _parse: function (b, d) {
            return "string" == typeof b ? d.parse(b, this) : b;
          },
        })),
        c = ((c.kdf = {}).OpenSSL = {
          execute: function (b, d, c, f) {
            f || (f = y.random(8));
            b = C.create({ keySize: d + c }).compute(b, f);
            c = y.create(b.words.slice(d), 4 * c);
            b.sigBytes = 4 * d;
            return I.create({ key: b, iv: c, salt: f });
          },
        }),
        n = (r.PasswordBasedCipher = d.extend({
          cfg: d.cfg.extend({ kdf: c }),
          encrypt: function (b, c, f, n) {
            n = this.cfg.extend(n);
            f = n.kdf.execute(f, b.keySize, b.ivSize);
            n.iv = f.iv;
            b = d.encrypt.call(this, b, c, f.key, n);
            b.mixIn(f);
            return b;
          },
          decrypt: function (b, c, f, n) {
            n = this.cfg.extend(n);
            c = this._parse(c, n.format);
            f = n.kdf.execute(f, b.keySize, b.ivSize, c.salt);
            n.iv = f.iv;
            return d.decrypt.call(this, b, c, f.key, n);
          },
        }));
    })();
  (function () {
    for (
      var h = b,
        c = h.lib.BlockCipher,
        r = h.algo,
        m = [],
        y = [],
        A = [],
        z = [],
        C = [],
        D = [],
        f = [],
        F = [],
        G = [],
        I = [],
        d = [],
        n = 0;
      256 > n;
      n++
    )
      d[n] = 128 > n ? n << 1 : (n << 1) ^ 283;
    for (var t = 0, p = 0, n = 0; 256 > n; n++) {
      var B = p ^ (p << 1) ^ (p << 2) ^ (p << 3) ^ (p << 4),
        B = (B >>> 8) ^ (B & 255) ^ 99;
      m[t] = B;
      y[B] = t;
      var E = d[t],
        H = d[E],
        L = d[H],
        J = (257 * d[B]) ^ (16843008 * B);
      A[t] = (J << 24) | (J >>> 8);
      z[t] = (J << 16) | (J >>> 16);
      C[t] = (J << 8) | (J >>> 24);
      D[t] = J;
      J = (16843009 * L) ^ (65537 * H) ^ (257 * E) ^ (16843008 * t);
      f[B] = (J << 24) | (J >>> 8);
      F[B] = (J << 16) | (J >>> 16);
      G[B] = (J << 8) | (J >>> 24);
      I[B] = J;
      t ? ((t = E ^ d[d[d[L ^ E]]]), (p ^= d[d[p]])) : (t = p = 1);
    }
    var M = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
      r = (r.AES = c.extend({
        _doReset: function () {
          for (
            var b = this._key,
              d = b.words,
              c = b.sigBytes / 4,
              b = 4 * ((this._nRounds = c + 6) + 1),
              n = (this._keySchedule = []),
              h = 0;
            h < b;
            h++
          )
            if (h < c) n[h] = d[h];
            else {
              var p = n[h - 1];
              h % c
                ? 6 < c &&
                  4 == h % c &&
                  (p =
                    (m[p >>> 24] << 24) |
                    (m[(p >>> 16) & 255] << 16) |
                    (m[(p >>> 8) & 255] << 8) |
                    m[p & 255])
                : ((p = (p << 8) | (p >>> 24)),
                  (p =
                    (m[p >>> 24] << 24) |
                    (m[(p >>> 16) & 255] << 16) |
                    (m[(p >>> 8) & 255] << 8) |
                    m[p & 255]),
                  (p ^= M[(h / c) | 0] << 24));
              n[h] = n[h - c] ^ p;
            }
          d = this._invKeySchedule = [];
          for (c = 0; c < b; c++)
            (h = b - c),
              (p = c % 4 ? n[h] : n[h - 4]),
              (d[c] =
                4 > c || 4 >= h
                  ? p
                  : f[m[p >>> 24]] ^
                    F[m[(p >>> 16) & 255]] ^
                    G[m[(p >>> 8) & 255]] ^
                    I[m[p & 255]]);
        },
        encryptBlock: function (b, d) {
          this._doCryptBlock(b, d, this._keySchedule, A, z, C, D, m);
        },
        decryptBlock: function (b, d) {
          var c = b[d + 1];
          b[d + 1] = b[d + 3];
          b[d + 3] = c;
          this._doCryptBlock(b, d, this._invKeySchedule, f, F, G, I, y);
          c = b[d + 1];
          b[d + 1] = b[d + 3];
          b[d + 3] = c;
        },
        _doCryptBlock: function (b, d, c, f, n, p, h, t) {
          for (
            var k = this._nRounds,
              m = b[d] ^ c[0],
              r = b[d + 1] ^ c[1],
              B = b[d + 2] ^ c[2],
              z = b[d + 3] ^ c[3],
              a = 4,
              e = 1;
            e < k;
            e++
          )
            var g =
                f[m >>> 24] ^
                n[(r >>> 16) & 255] ^
                p[(B >>> 8) & 255] ^
                h[z & 255] ^
                c[a++],
              R =
                f[r >>> 24] ^
                n[(B >>> 16) & 255] ^
                p[(z >>> 8) & 255] ^
                h[m & 255] ^
                c[a++],
              l =
                f[B >>> 24] ^
                n[(z >>> 16) & 255] ^
                p[(m >>> 8) & 255] ^
                h[r & 255] ^
                c[a++],
              z =
                f[z >>> 24] ^
                n[(m >>> 16) & 255] ^
                p[(r >>> 8) & 255] ^
                h[B & 255] ^
                c[a++],
              m = g,
              r = R,
              B = l;
          g =
            ((t[m >>> 24] << 24) |
              (t[(r >>> 16) & 255] << 16) |
              (t[(B >>> 8) & 255] << 8) |
              t[z & 255]) ^
            c[a++];
          R =
            ((t[r >>> 24] << 24) |
              (t[(B >>> 16) & 255] << 16) |
              (t[(z >>> 8) & 255] << 8) |
              t[m & 255]) ^
            c[a++];
          l =
            ((t[B >>> 24] << 24) |
              (t[(z >>> 16) & 255] << 16) |
              (t[(m >>> 8) & 255] << 8) |
              t[r & 255]) ^
            c[a++];
          z =
            ((t[z >>> 24] << 24) |
              (t[(m >>> 16) & 255] << 16) |
              (t[(r >>> 8) & 255] << 8) |
              t[B & 255]) ^
            c[a++];
          b[d] = g;
          b[d + 1] = R;
          b[d + 2] = l;
          b[d + 3] = z;
        },
        keySize: 8,
      }));
    h.AES = c._createHelper(r);
  })();
  L.CryptoJS = b;
})(com_sbps_system);
com_sbps_system = com_sbps_system || {};
(function (L) {
  var b = L.CryptoJS,
    b =
      b ||
      (function (b, c) {
        var r = {},
          m = (r.lib = {}),
          y = function () {},
          A = (m.Base = {
            extend: function (b) {
              y.prototype = this;
              var c = new y();
              b && c.mixIn(b);
              c.hasOwnProperty("init") ||
                (c.init = function () {
                  c.$super.init.apply(this, arguments);
                });
              c.init.prototype = c;
              c.$super = this;
              return c;
            },
            create: function () {
              var b = this.extend();
              b.init.apply(b, arguments);
              return b;
            },
            init: function () {},
            mixIn: function (b) {
              for (var c in b) b.hasOwnProperty(c) && (this[c] = b[c]);
              b.hasOwnProperty("toString") && (this.toString = b.toString);
            },
            clone: function () {
              return this.init.prototype.extend(this);
            },
          }),
          z = (m.WordArray = A.extend({
            init: function (b, f) {
              b = this.words = b || [];
              this.sigBytes = f != c ? f : 4 * b.length;
            },
            toString: function (b) {
              return (b || D).stringify(this);
            },
            concat: function (b) {
              var c = this.words,
                f = b.words,
                p = this.sigBytes;
              b = b.sigBytes;
              this.clamp();
              if (p % 4)
                for (var h = 0; h < b; h++)
                  c[(p + h) >>> 2] |=
                    ((f[h >>> 2] >>> (24 - (h % 4) * 8)) & 255) <<
                    (24 - ((p + h) % 4) * 8);
              else if (65535 < f.length)
                for (h = 0; h < b; h += 4) c[(p + h) >>> 2] = f[h >>> 2];
              else c.push.apply(c, f);
              this.sigBytes += b;
              return this;
            },
            clamp: function () {
              var d = this.words,
                c = this.sigBytes;
              d[c >>> 2] &= 4294967295 << (32 - (c % 4) * 8);
              d.length = b.ceil(c / 4);
            },
            clone: function () {
              var b = A.clone.call(this);
              b.words = this.words.slice(0);
              return b;
            },
            random: function (d) {
              for (var c = [], f = 0; f < d; f += 4)
                c.push((4294967296 * b.random()) | 0);
              return new z.init(c, d);
            },
          })),
          C = (r.enc = {}),
          D = (C.Hex = {
            stringify: function (b) {
              var c = b.words;
              b = b.sigBytes;
              for (var f = [], h = 0; h < b; h++) {
                var m = (c[h >>> 2] >>> (24 - (h % 4) * 8)) & 255;
                f.push((m >>> 4).toString(16));
                f.push((m & 15).toString(16));
              }
              return f.join("");
            },
            parse: function (b) {
              for (var c = b.length, f = [], h = 0; h < c; h += 2)
                f[h >>> 3] |=
                  parseInt(b.substr(h, 2), 16) << (24 - (h % 8) * 4);
              return new z.init(f, c / 2);
            },
          }),
          f = (C.Latin1 = {
            stringify: function (b) {
              var c = b.words;
              b = b.sigBytes;
              for (var f = [], h = 0; h < b; h++)
                f.push(
                  String.fromCharCode((c[h >>> 2] >>> (24 - (h % 4) * 8)) & 255)
                );
              return f.join("");
            },
            parse: function (b) {
              for (var c = b.length, f = [], h = 0; h < c; h++)
                f[h >>> 2] |= (b.charCodeAt(h) & 255) << (24 - (h % 4) * 8);
              return new z.init(f, c);
            },
          }),
          F = (C.Utf8 = {
            stringify: function (b) {
              try {
                return decodeURIComponent(escape(f.stringify(b)));
              } catch (c) {
                throw Error("Malformed UTF-8 data");
              }
            },
            parse: function (b) {
              return f.parse(unescape(encodeURIComponent(b)));
            },
          }),
          G = (m.BufferedBlockAlgorithm = A.extend({
            reset: function () {
              this._data = new z.init();
              this._nDataBytes = 0;
            },
            _append: function (b) {
              "string" == typeof b && (b = F.parse(b));
              this._data.concat(b);
              this._nDataBytes += b.sigBytes;
            },
            _process: function (c) {
              var f = this._data,
                m = f.words,
                p = f.sigBytes,
                r = this.blockSize,
                y = p / (4 * r),
                y = c ? b.ceil(y) : b.max((y | 0) - this._minBufferSize, 0);
              c = y * r;
              p = b.min(4 * c, p);
              if (c) {
                for (var A = 0; A < c; A += r) this._doProcessBlock(m, A);
                A = m.splice(0, c);
                f.sigBytes -= p;
              }
              return new z.init(A, p);
            },
            clone: function () {
              var b = A.clone.call(this);
              b._data = this._data.clone();
              return b;
            },
            _minBufferSize: 0,
          }));
        m.Hasher = G.extend({
          cfg: A.extend(),
          init: function (b) {
            this.cfg = this.cfg.extend(b);
            this.reset();
          },
          reset: function () {
            G.reset.call(this);
            this._doReset();
          },
          update: function (b) {
            this._append(b);
            this._process();
            return this;
          },
          finalize: function (b) {
            b && this._append(b);
            return this._doFinalize();
          },
          blockSize: 16,
          _createHelper: function (b) {
            return function (c, f) {
              return new b.init(f).finalize(c);
            };
          },
          _createHmacHelper: function (b) {
            return function (c, f) {
              return new I.HMAC.init(b, f).finalize(c);
            };
          },
        });
        var I = (r.algo = {});
        return r;
      })(Math);
  (function () {
    var h = b,
      c = h.lib,
      r = c.WordArray,
      m = c.Hasher,
      y = [],
      c = (h.algo.SHA1 = m.extend({
        _doReset: function () {
          this._hash = new r.init([
            1732584193, 4023233417, 2562383102, 271733878, 3285377520,
          ]);
        },
        _doProcessBlock: function (b, c) {
          for (
            var h = this._hash.words,
              m = h[0],
              f = h[1],
              r = h[2],
              G = h[3],
              I = h[4],
              d = 0;
            80 > d;
            d++
          ) {
            if (16 > d) y[d] = b[c + d] | 0;
            else {
              var n = y[d - 3] ^ y[d - 8] ^ y[d - 14] ^ y[d - 16];
              y[d] = (n << 1) | (n >>> 31);
            }
            n = ((m << 5) | (m >>> 27)) + I + y[d];
            n =
              20 > d
                ? n + (((f & r) | (~f & G)) + 1518500249)
                : 40 > d
                ? n + ((f ^ r ^ G) + 1859775393)
                : 60 > d
                ? n + (((f & r) | (f & G) | (r & G)) - 1894007588)
                : n + ((f ^ r ^ G) - 899497514);
            I = G;
            G = r;
            r = (f << 30) | (f >>> 2);
            f = m;
            m = n;
          }
          h[0] = (h[0] + m) | 0;
          h[1] = (h[1] + f) | 0;
          h[2] = (h[2] + r) | 0;
          h[3] = (h[3] + G) | 0;
          h[4] = (h[4] + I) | 0;
        },
        _doFinalize: function () {
          var b = this._data,
            c = b.words,
            h = 8 * this._nDataBytes,
            m = 8 * b.sigBytes;
          c[m >>> 5] |= 128 << (24 - (m % 32));
          c[(((m + 64) >>> 9) << 4) + 14] = Math.floor(h / 4294967296);
          c[(((m + 64) >>> 9) << 4) + 15] = h;
          b.sigBytes = 4 * c.length;
          this._process();
          return this._hash;
        },
        clone: function () {
          var b = m.clone.call(this);
          b._hash = this._hash.clone();
          return b;
        },
      }));
    h.SHA1 = m._createHelper(c);
    h.HmacSHA1 = m._createHmacHelper(c);
  })();
  (function () {
    var h = b,
      c = h.enc.Utf8;
    h.algo.HMAC = h.lib.Base.extend({
      init: function (b, h) {
        b = this._hasher = new b.init();
        "string" == typeof h && (h = c.parse(h));
        var y = b.blockSize,
          A = 4 * y;
        h.sigBytes > A && (h = b.finalize(h));
        h.clamp();
        for (
          var z = (this._oKey = h.clone()),
            C = (this._iKey = h.clone()),
            D = z.words,
            f = C.words,
            F = 0;
          F < y;
          F++
        )
          (D[F] ^= 1549556828), (f[F] ^= 909522486);
        z.sigBytes = C.sigBytes = A;
        this.reset();
      },
      reset: function () {
        var b = this._hasher;
        b.reset();
        b.update(this._iKey);
      },
      update: function (b) {
        this._hasher.update(b);
        return this;
      },
      finalize: function (b) {
        var c = this._hasher;
        b = c.finalize(b);
        c.reset();
        return c.finalize(this._oKey.clone().concat(b));
      },
    });
  })();
  (function () {
    var h = b,
      c = h.lib,
      r = c.Base,
      m = c.WordArray,
      c = h.algo,
      y = c.HMAC,
      A = (c.PBKDF2 = r.extend({
        cfg: r.extend({ keySize: 4, hasher: c.SHA1, iterations: 1 }),
        init: function (b) {
          this.cfg = this.cfg.extend(b);
        },
        compute: function (b, c) {
          for (
            var h = this.cfg,
              f = y.create(h.hasher, b),
              r = m.create(),
              A = m.create([1]),
              I = r.words,
              d = A.words,
              n = h.keySize,
              h = h.iterations;
            I.length < n;

          ) {
            var t = f.update(c).finalize(A);
            f.reset();
            for (var p = t.words, B = p.length, E = t, H = 1; H < h; H++) {
              E = f.finalize(E);
              f.reset();
              for (var L = E.words, J = 0; J < B; J++) p[J] ^= L[J];
            }
            r.concat(t);
            d[0]++;
          }
          r.sigBytes = 4 * n;
          return r;
        },
      }));
    h.PBKDF2 = function (b, c, h) {
      return A.create(h).compute(b, c);
    };
  })();
  L.CryptoJS = b;
})(com_sbps_system); /*
 JSEncrypt v2.3.1
 Copyright (c) 2005  Tom Wu
 All Rights Reserved.
 See https://npmcdn.com/jsencrypt@2.3.1/LICENSE.txt
 <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
*/
com_sbps_system = com_sbps_system || {};
(function (L, b) {
  "function" === typeof define && define.amd
    ? define(["exports"], b)
    : "object" === typeof exports && "string" !== typeof exports.nodeName
    ? b(module.exports)
    : b(L);
})(com_sbps_system, function (L) {
  function b(a, e, g) {
    null != a &&
      ("number" == typeof a
        ? this.fromNumber(a, e, g)
        : null == e && "string" != typeof a
        ? this.fromString(a, 256)
        : this.fromString(a, e));
  }
  function h() {
    return new b(null);
  }
  function c(a, e, g, b, l, c) {
    for (; 0 <= --c; ) {
      var q = e * this[a++] + g[b] + l;
      l = Math.floor(q / 67108864);
      g[b++] = q & 67108863;
    }
    return l;
  }
  function r(a, e, g, b, l, c) {
    var q = e & 32767;
    for (e >>= 15; 0 <= --c; ) {
      var d = this[a] & 32767,
        h = this[a++] >> 15,
        f = e * d + h * q,
        d = q * d + ((f & 32767) << 15) + g[b] + (l & 1073741823);
      l = (d >>> 30) + (f >>> 15) + e * h + (l >>> 30);
      g[b++] = d & 1073741823;
    }
    return l;
  }
  function m(a, e, g, b, l, c) {
    var q = e & 16383;
    for (e >>= 14; 0 <= --c; ) {
      var d = this[a] & 16383,
        h = this[a++] >> 14,
        f = e * d + h * q,
        d = q * d + ((f & 16383) << 14) + g[b] + l;
      l = (d >> 28) + (f >> 14) + e * h;
      g[b++] = d & 268435455;
    }
    return l;
  }
  function y(a, e) {
    var g = U[a.charCodeAt(e)];
    return null == g ? -1 : g;
  }
  function A(a) {
    var e = h();
    e.fromInt(a);
    return e;
  }
  function z(a) {
    var e = 1,
      g;
    0 != (g = a >>> 16) && ((a = g), (e += 16));
    0 != (g = a >> 8) && ((a = g), (e += 8));
    0 != (g = a >> 4) && ((a = g), (e += 4));
    0 != (g = a >> 2) && ((a = g), (e += 2));
    0 != a >> 1 && (e += 1);
    return e;
  }
  function C(a) {
    this.m = a;
  }
  function D(a) {
    this.m = a;
    this.mp = a.invDigit();
    this.mpl = this.mp & 32767;
    this.mph = this.mp >> 15;
    this.um = (1 << (a.DB - 15)) - 1;
    this.mt2 = 2 * a.t;
  }
  function f(a, e) {
    return a & e;
  }
  function F(a, e) {
    return a | e;
  }
  function G(a, e) {
    return a ^ e;
  }
  function I(a, e) {
    return a & ~e;
  }
  function d() {}
  function n(a) {
    return a;
  }
  function t(a) {
    this.r2 = h();
    this.q3 = h();
    b.ONE.dlShiftTo(2 * a.t, this.r2);
    this.mu = this.r2.divide(a);
    this.m = a;
  }
  function p() {
    this.j = this.i = 0;
    this.S = [];
  }
  function B() {}
  function E(a, e) {
    return new b(a, e);
  }
  function H() {
    this.n = null;
    this.e = 0;
    this.coeff = this.dmq1 = this.dmp1 = this.q = this.p = this.d = null;
  }
  function V(a) {
    var e,
      g,
      b = "";
    for (e = 0; e + 3 <= a.length; e += 3)
      (g = parseInt(a.substring(e, e + 3), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            g >> 6
          ) +
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            g & 63
          ));
    e + 1 == a.length
      ? ((g = parseInt(a.substring(e, e + 1), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            g << 2
          )))
      : e + 2 == a.length &&
        ((g = parseInt(a.substring(e, e + 2), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            g >> 2
          ) +
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            (g & 3) << 4
          )));
    for (; 0 < (b.length & 3); ) b += "=";
    return b;
  }
  function J(a) {
    var e = "",
      g,
      b = 0,
      l;
    for (g = 0; g < a.length && "=" != a.charAt(g); ++g)
      (v =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(
          a.charAt(g)
        )),
        0 > v ||
          (0 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v >> 2)),
              (l = v & 3),
              (b = 1))
            : 1 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(
                (l << 2) | (v >> 4)
              )),
              (l = v & 15),
              (b = 2))
            : 2 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(l)),
              (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v >> 2)),
              (l = v & 3),
              (b = 3))
            : ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(
                (l << 2) | (v >> 4)
              )),
              (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v & 15)),
              (b = 0)));
    1 == b && (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(l << 2));
    return e;
  }
  var M;
  "Microsoft Internet Explorer" == navigator.appName
    ? ((b.prototype.am = r), (M = 30))
    : "Netscape" != navigator.appName
    ? ((b.prototype.am = c), (M = 26))
    : ((b.prototype.am = m), (M = 28));
  b.prototype.DB = M;
  b.prototype.DM = (1 << M) - 1;
  b.prototype.DV = 1 << M;
  b.prototype.FV = Math.pow(2, 52);
  b.prototype.F1 = 52 - M;
  b.prototype.F2 = 2 * M - 52;
  var U = [],
    K;
  M = 48;
  for (K = 0; 9 >= K; ++K) U[M++] = K;
  M = 97;
  for (K = 10; 36 > K; ++K) U[M++] = K;
  M = 65;
  for (K = 10; 36 > K; ++K) U[M++] = K;
  C.prototype.convert = function (a) {
    return 0 > a.s || 0 <= a.compareTo(this.m) ? a.mod(this.m) : a;
  };
  C.prototype.revert = function (a) {
    return a;
  };
  C.prototype.reduce = function (a) {
    a.divRemTo(this.m, null, a);
  };
  C.prototype.mulTo = function (a, e, g) {
    a.multiplyTo(e, g);
    this.reduce(g);
  };
  C.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
    this.reduce(e);
  };
  D.prototype.convert = function (a) {
    var e = h();
    a.abs().dlShiftTo(this.m.t, e);
    e.divRemTo(this.m, null, e);
    0 > a.s && 0 < e.compareTo(b.ZERO) && this.m.subTo(e, e);
    return e;
  };
  D.prototype.revert = function (a) {
    var e = h();
    a.copyTo(e);
    this.reduce(e);
    return e;
  };
  D.prototype.reduce = function (a) {
    for (; a.t <= this.mt2; ) a[a.t++] = 0;
    for (var e = 0; e < this.m.t; ++e) {
      var g = a[e] & 32767,
        b =
          (g * this.mpl +
            (((g * this.mph + (a[e] >> 15) * this.mpl) & this.um) << 15)) &
          a.DM,
        g = e + this.m.t;
      for (a[g] += this.m.am(0, b, a, e, 0, this.m.t); a[g] >= a.DV; )
        (a[g] -= a.DV), a[++g]++;
    }
    a.clamp();
    a.drShiftTo(this.m.t, a);
    0 <= a.compareTo(this.m) && a.subTo(this.m, a);
  };
  D.prototype.mulTo = function (a, e, g) {
    a.multiplyTo(e, g);
    this.reduce(g);
  };
  D.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
    this.reduce(e);
  };
  b.prototype.copyTo = function (a) {
    for (var e = this.t - 1; 0 <= e; --e) a[e] = this[e];
    a.t = this.t;
    a.s = this.s;
  };
  b.prototype.fromInt = function (a) {
    this.t = 1;
    this.s = 0 > a ? -1 : 0;
    0 < a ? (this[0] = a) : -1 > a ? (this[0] = a + this.DV) : (this.t = 0);
  };
  b.prototype.fromString = function (a, e) {
    var g;
    if (16 == e) g = 4;
    else if (8 == e) g = 3;
    else if (256 == e) g = 8;
    else if (2 == e) g = 1;
    else if (32 == e) g = 5;
    else if (4 == e) g = 2;
    else {
      this.fromRadix(a, e);
      return;
    }
    this.s = this.t = 0;
    for (var R = a.length, l = !1, c = 0; 0 <= --R; ) {
      var q = 8 == g ? a[R] & 255 : y(a, R);
      0 > q
        ? "-" == a.charAt(R) && (l = !0)
        : ((l = !1),
          0 == c
            ? (this[this.t++] = q)
            : c + g > this.DB
            ? ((this[this.t - 1] |= (q & ((1 << (this.DB - c)) - 1)) << c),
              (this[this.t++] = q >> (this.DB - c)))
            : (this[this.t - 1] |= q << c),
          (c += g),
          c >= this.DB && (c -= this.DB));
    }
    8 == g &&
      0 != (a[0] & 128) &&
      ((this.s = -1),
      0 < c && (this[this.t - 1] |= ((1 << (this.DB - c)) - 1) << c));
    this.clamp();
    l && b.ZERO.subTo(this, this);
  };
  b.prototype.clamp = function () {
    for (var a = this.s & this.DM; 0 < this.t && this[this.t - 1] == a; )
      --this.t;
  };
  b.prototype.dlShiftTo = function (a, e) {
    var g;
    for (g = this.t - 1; 0 <= g; --g) e[g + a] = this[g];
    for (g = a - 1; 0 <= g; --g) e[g] = 0;
    e.t = this.t + a;
    e.s = this.s;
  };
  b.prototype.drShiftTo = function (a, e) {
    for (var g = a; g < this.t; ++g) e[g - a] = this[g];
    e.t = Math.max(this.t - a, 0);
    e.s = this.s;
  };
  b.prototype.lShiftTo = function (a, e) {
    var g = a % this.DB,
      b = this.DB - g,
      l = (1 << b) - 1,
      c = Math.floor(a / this.DB),
      q = (this.s << g) & this.DM,
      d;
    for (d = this.t - 1; 0 <= d; --d)
      (e[d + c + 1] = (this[d] >> b) | q), (q = (this[d] & l) << g);
    for (d = c - 1; 0 <= d; --d) e[d] = 0;
    e[c] = q;
    e.t = this.t + c + 1;
    e.s = this.s;
    e.clamp();
  };
  b.prototype.rShiftTo = function (a, e) {
    e.s = this.s;
    var g = Math.floor(a / this.DB);
    if (g >= this.t) e.t = 0;
    else {
      var b = a % this.DB,
        l = this.DB - b,
        c = (1 << b) - 1;
      e[0] = this[g] >> b;
      for (var q = g + 1; q < this.t; ++q)
        (e[q - g - 1] |= (this[q] & c) << l), (e[q - g] = this[q] >> b);
      0 < b && (e[this.t - g - 1] |= (this.s & c) << l);
      e.t = this.t - g;
      e.clamp();
    }
  };
  b.prototype.subTo = function (a, e) {
    for (var g = 0, b = 0, l = Math.min(a.t, this.t); g < l; )
      (b += this[g] - a[g]), (e[g++] = b & this.DM), (b >>= this.DB);
    if (a.t < this.t) {
      for (b -= a.s; g < this.t; )
        (b += this[g]), (e[g++] = b & this.DM), (b >>= this.DB);
      b += this.s;
    } else {
      for (b += this.s; g < a.t; )
        (b -= a[g]), (e[g++] = b & this.DM), (b >>= this.DB);
      b -= a.s;
    }
    e.s = 0 > b ? -1 : 0;
    -1 > b ? (e[g++] = this.DV + b) : 0 < b && (e[g++] = b);
    e.t = g;
    e.clamp();
  };
  b.prototype.multiplyTo = function (a, e) {
    var g = this.abs(),
      c = a.abs(),
      l = g.t;
    for (e.t = l + c.t; 0 <= --l; ) e[l] = 0;
    for (l = 0; l < c.t; ++l) e[l + g.t] = g.am(0, c[l], e, l, 0, g.t);
    e.s = 0;
    e.clamp();
    this.s != a.s && b.ZERO.subTo(e, e);
  };
  b.prototype.squareTo = function (a) {
    for (var e = this.abs(), g = (a.t = 2 * e.t); 0 <= --g; ) a[g] = 0;
    for (g = 0; g < e.t - 1; ++g) {
      var b = e.am(g, e[g], a, 2 * g, 0, 1);
      (a[g + e.t] += e.am(g + 1, 2 * e[g], a, 2 * g + 1, b, e.t - g - 1)) >=
        e.DV && ((a[g + e.t] -= e.DV), (a[g + e.t + 1] = 1));
    }
    0 < a.t && (a[a.t - 1] += e.am(g, e[g], a, 2 * g, 0, 1));
    a.s = 0;
    a.clamp();
  };
  b.prototype.divRemTo = function (a, e, g) {
    var c = a.abs();
    if (!(0 >= c.t)) {
      var l = this.abs();
      if (l.t < c.t) null != e && e.fromInt(0), null != g && this.copyTo(g);
      else {
        null == g && (g = h());
        var d = h(),
          q = this.s;
        a = a.s;
        var f = this.DB - z(c[c.t - 1]);
        0 < f
          ? (c.lShiftTo(f, d), l.lShiftTo(f, g))
          : (c.copyTo(d), l.copyTo(g));
        c = d.t;
        l = d[c - 1];
        if (0 != l) {
          var k = l * (1 << this.F1) + (1 < c ? d[c - 2] >> this.F2 : 0),
            m = this.FV / k,
            k = (1 << this.F1) / k,
            p = 1 << this.F2,
            r = g.t,
            n = r - c,
            t = null == e ? h() : e;
          d.dlShiftTo(n, t);
          0 <= g.compareTo(t) && ((g[g.t++] = 1), g.subTo(t, g));
          b.ONE.dlShiftTo(c, t);
          for (t.subTo(d, d); d.t < c; ) d[d.t++] = 0;
          for (; 0 <= --n; ) {
            var u =
              g[--r] == l ? this.DM : Math.floor(g[r] * m + (g[r - 1] + p) * k);
            if ((g[r] += d.am(0, u, g, n, 0, c)) < u)
              for (d.dlShiftTo(n, t), g.subTo(t, g); g[r] < --u; )
                g.subTo(t, g);
          }
          null != e && (g.drShiftTo(c, e), q != a && b.ZERO.subTo(e, e));
          g.t = c;
          g.clamp();
          0 < f && g.rShiftTo(f, g);
          0 > q && b.ZERO.subTo(g, g);
        }
      }
    }
  };
  b.prototype.invDigit = function () {
    if (1 > this.t) return 0;
    var a = this[0];
    if (0 == (a & 1)) return 0;
    var e = a & 3,
      e = (e * (2 - (a & 15) * e)) & 15,
      e = (e * (2 - (a & 255) * e)) & 255,
      e = (e * (2 - (((a & 65535) * e) & 65535))) & 65535,
      e = (e * (2 - ((a * e) % this.DV))) % this.DV;
    return 0 < e ? this.DV - e : -e;
  };
  b.prototype.isEven = function () {
    return 0 == (0 < this.t ? this[0] & 1 : this.s);
  };
  b.prototype.exp = function (a, e) {
    if (4294967295 < a || 1 > a) return b.ONE;
    var g = h(),
      c = h(),
      l = e.convert(this),
      d = z(a) - 1;
    for (l.copyTo(g); 0 <= --d; )
      if ((e.sqrTo(g, c), 0 < (a & (1 << d)))) e.mulTo(c, l, g);
      else
        var q = g,
          g = c,
          c = q;
    return e.revert(g);
  };
  b.prototype.toString = function (a) {
    if (0 > this.s) return "-" + this.negate().toString(a);
    if (16 == a) a = 4;
    else if (8 == a) a = 3;
    else if (2 == a) a = 1;
    else if (32 == a) a = 5;
    else if (4 == a) a = 2;
    else return this.toRadix(a);
    var e = (1 << a) - 1,
      g,
      b = !1,
      l = "",
      c = this.t,
      d = this.DB - ((c * this.DB) % a);
    if (0 < c--)
      for (
        d < this.DB &&
        0 < (g = this[c] >> d) &&
        ((b = !0), (l = "0123456789abcdefghijklmnopqrstuvwxyz".charAt(g)));
        0 <= c;

      )
        d < a
          ? ((g = (this[c] & ((1 << d) - 1)) << (a - d)),
            (g |= this[--c] >> (d += this.DB - a)))
          : ((g = (this[c] >> (d -= a)) & e), 0 >= d && ((d += this.DB), --c)),
          0 < g && (b = !0),
          b && (l += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(g));
    return b ? l : "0";
  };
  b.prototype.negate = function () {
    var a = h();
    b.ZERO.subTo(this, a);
    return a;
  };
  b.prototype.abs = function () {
    return 0 > this.s ? this.negate() : this;
  };
  b.prototype.compareTo = function (a) {
    var e = this.s - a.s;
    if (0 != e) return e;
    var g = this.t,
      e = g - a.t;
    if (0 != e) return 0 > this.s ? -e : e;
    for (; 0 <= --g; ) if (0 != (e = this[g] - a[g])) return e;
    return 0;
  };
  b.prototype.bitLength = function () {
    return 0 >= this.t
      ? 0
      : this.DB * (this.t - 1) + z(this[this.t - 1] ^ (this.s & this.DM));
  };
  b.prototype.mod = function (a) {
    var e = h();
    this.abs().divRemTo(a, null, e);
    0 > this.s && 0 < e.compareTo(b.ZERO) && a.subTo(e, e);
    return e;
  };
  b.prototype.modPowInt = function (a, e) {
    var g;
    g = 256 > a || e.isEven() ? new C(e) : new D(e);
    return this.exp(a, g);
  };
  b.ZERO = A(0);
  b.ONE = A(1);
  d.prototype.convert = n;
  d.prototype.revert = n;
  d.prototype.mulTo = function (a, e, g) {
    a.multiplyTo(e, g);
  };
  d.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
  };
  t.prototype.convert = function (a) {
    if (0 > a.s || a.t > 2 * this.m.t) return a.mod(this.m);
    if (0 > a.compareTo(this.m)) return a;
    var e = h();
    a.copyTo(e);
    this.reduce(e);
    return e;
  };
  t.prototype.revert = function (a) {
    return a;
  };
  t.prototype.reduce = function (a) {
    a.drShiftTo(this.m.t - 1, this.r2);
    a.t > this.m.t + 1 && ((a.t = this.m.t + 1), a.clamp());
    this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
    for (
      this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
      0 > a.compareTo(this.r2);

    )
      a.dAddOffset(1, this.m.t + 1);
    for (a.subTo(this.r2, a); 0 <= a.compareTo(this.m); ) a.subTo(this.m, a);
  };
  t.prototype.mulTo = function (a, e, g) {
    a.multiplyTo(e, g);
    this.reduce(g);
  };
  t.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
    this.reduce(e);
  };
  var N = [
      2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
      71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
      151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
      233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
      317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409,
      419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
      503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601,
      607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691,
      701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809,
      811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907,
      911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997,
    ],
    S = 67108864 / N[N.length - 1];
  b.prototype.chunkSize = function (a) {
    return Math.floor((Math.LN2 * this.DB) / Math.log(a));
  };
  b.prototype.toRadix = function (a) {
    null == a && (a = 10);
    if (0 == this.signum() || 2 > a || 36 < a) return "0";
    var e = this.chunkSize(a),
      e = Math.pow(a, e),
      g = A(e),
      b = h(),
      c = h(),
      d = "";
    for (this.divRemTo(g, b, c); 0 < b.signum(); )
      (d = (e + c.intValue()).toString(a).substr(1) + d), b.divRemTo(g, b, c);
    return c.intValue().toString(a) + d;
  };
  b.prototype.fromRadix = function (a, e) {
    this.fromInt(0);
    null == e && (e = 10);
    for (
      var g = this.chunkSize(e),
        c = Math.pow(e, g),
        l = !1,
        d = 0,
        q = 0,
        f = 0;
      f < a.length;
      ++f
    ) {
      var h = y(a, f);
      0 > h
        ? "-" == a.charAt(f) && 0 == this.signum() && (l = !0)
        : ((q = e * q + h),
          ++d >= g && (this.dMultiply(c), this.dAddOffset(q, 0), (q = d = 0)));
    }
    0 < d && (this.dMultiply(Math.pow(e, d)), this.dAddOffset(q, 0));
    l && b.ZERO.subTo(this, this);
  };
  b.prototype.fromNumber = function (a, e, g) {
    if ("number" == typeof e)
      if (2 > a) this.fromInt(1);
      else
        for (
          this.fromNumber(a, g),
            this.testBit(a - 1) ||
              this.bitwiseTo(b.ONE.shiftLeft(a - 1), F, this),
            this.isEven() && this.dAddOffset(1, 0);
          !this.isProbablePrime(e);

        )
          this.dAddOffset(2, 0),
            this.bitLength() > a && this.subTo(b.ONE.shiftLeft(a - 1), this);
    else {
      g = [];
      var c = a & 7;
      g.length = (a >> 3) + 1;
      e.nextBytes(g);
      g[0] = 0 < c ? g[0] & ((1 << c) - 1) : 0;
      this.fromString(g, 256);
    }
  };
  b.prototype.bitwiseTo = function (a, e, b) {
    var c,
      l,
      d = Math.min(a.t, this.t);
    for (c = 0; c < d; ++c) b[c] = e(this[c], a[c]);
    if (a.t < this.t) {
      l = a.s & this.DM;
      for (c = d; c < this.t; ++c) b[c] = e(this[c], l);
      b.t = this.t;
    } else {
      l = this.s & this.DM;
      for (c = d; c < a.t; ++c) b[c] = e(l, a[c]);
      b.t = a.t;
    }
    b.s = e(this.s, a.s);
    b.clamp();
  };
  b.prototype.changeBit = function (a, e) {
    var g = b.ONE.shiftLeft(a);
    this.bitwiseTo(g, e, g);
    return g;
  };
  b.prototype.addTo = function (a, e) {
    for (var b = 0, c = 0, l = Math.min(a.t, this.t); b < l; )
      (c += this[b] + a[b]), (e[b++] = c & this.DM), (c >>= this.DB);
    if (a.t < this.t) {
      for (c += a.s; b < this.t; )
        (c += this[b]), (e[b++] = c & this.DM), (c >>= this.DB);
      c += this.s;
    } else {
      for (c += this.s; b < a.t; )
        (c += a[b]), (e[b++] = c & this.DM), (c >>= this.DB);
      c += a.s;
    }
    e.s = 0 > c ? -1 : 0;
    0 < c ? (e[b++] = c) : -1 > c && (e[b++] = this.DV + c);
    e.t = b;
    e.clamp();
  };
  b.prototype.dMultiply = function (a) {
    this[this.t] = this.am(0, a - 1, this, 0, 0, this.t);
    ++this.t;
    this.clamp();
  };
  b.prototype.dAddOffset = function (a, e) {
    if (0 != a) {
      for (; this.t <= e; ) this[this.t++] = 0;
      for (this[e] += a; this[e] >= this.DV; )
        (this[e] -= this.DV), ++e >= this.t && (this[this.t++] = 0), ++this[e];
    }
  };
  b.prototype.multiplyLowerTo = function (a, e, b) {
    var c = Math.min(this.t + a.t, e);
    b.s = 0;
    for (b.t = c; 0 < c; ) b[--c] = 0;
    var l;
    for (l = b.t - this.t; c < l; ++c)
      b[c + this.t] = this.am(0, a[c], b, c, 0, this.t);
    for (l = Math.min(a.t, e); c < l; ++c) this.am(0, a[c], b, c, 0, e - c);
    b.clamp();
  };
  b.prototype.multiplyUpperTo = function (a, e, b) {
    --e;
    var c = (b.t = this.t + a.t - e);
    for (b.s = 0; 0 <= --c; ) b[c] = 0;
    for (c = Math.max(e - this.t, 0); c < a.t; ++c)
      b[this.t + c - e] = this.am(e - c, a[c], b, 0, 0, this.t + c - e);
    b.clamp();
    b.drShiftTo(1, b);
  };
  b.prototype.modInt = function (a) {
    if (0 >= a) return 0;
    var e = this.DV % a,
      b = 0 > this.s ? a - 1 : 0;
    if (0 < this.t)
      if (0 == e) b = this[0] % a;
      else for (var c = this.t - 1; 0 <= c; --c) b = (e * b + this[c]) % a;
    return b;
  };
  b.prototype.millerRabin = function (a) {
    var e = this.subtract(b.ONE),
      g = e.getLowestSetBit();
    if (0 >= g) return !1;
    var c = e.shiftRight(g);
    a = (a + 1) >> 1;
    a > N.length && (a = N.length);
    for (var l = h(), d = 0; d < a; ++d) {
      l.fromInt(N[Math.floor(Math.random() * N.length)]);
      var q = l.modPow(c, this);
      if (0 != q.compareTo(b.ONE) && 0 != q.compareTo(e)) {
        for (var f = 1; f++ < g && 0 != q.compareTo(e); )
          if (((q = q.modPowInt(2, this)), 0 == q.compareTo(b.ONE))) return !1;
        if (0 != q.compareTo(e)) return !1;
      }
    }
    return !0;
  };
  b.prototype.clone = function () {
    var a = h();
    this.copyTo(a);
    return a;
  };
  b.prototype.intValue = function () {
    if (0 > this.s) {
      if (1 == this.t) return this[0] - this.DV;
      if (0 == this.t) return -1;
    } else {
      if (1 == this.t) return this[0];
      if (0 == this.t) return 0;
    }
    return ((this[1] & ((1 << (32 - this.DB)) - 1)) << this.DB) | this[0];
  };
  b.prototype.byteValue = function () {
    return 0 == this.t ? this.s : (this[0] << 24) >> 24;
  };
  b.prototype.shortValue = function () {
    return 0 == this.t ? this.s : (this[0] << 16) >> 16;
  };
  b.prototype.signum = function () {
    return 0 > this.s
      ? -1
      : 0 >= this.t || (1 == this.t && 0 >= this[0])
      ? 0
      : 1;
  };
  b.prototype.toByteArray = function () {
    var a = this.t,
      e = [];
    e[0] = this.s;
    var b = this.DB - ((a * this.DB) % 8),
      c,
      l = 0;
    if (0 < a--)
      for (
        b < this.DB &&
        (c = this[a] >> b) != (this.s & this.DM) >> b &&
        (e[l++] = c | (this.s << (this.DB - b)));
        0 <= a;

      )
        if (
          (8 > b
            ? ((c = (this[a] & ((1 << b) - 1)) << (8 - b)),
              (c |= this[--a] >> (b += this.DB - 8)))
            : ((c = (this[a] >> (b -= 8)) & 255),
              0 >= b && ((b += this.DB), --a)),
          0 != (c & 128) && (c |= -256),
          0 == l && (this.s & 128) != (c & 128) && ++l,
          0 < l || c != this.s)
        )
          e[l++] = c;
    return e;
  };
  b.prototype.equals = function (a) {
    return 0 == this.compareTo(a);
  };
  b.prototype.min = function (a) {
    return 0 > this.compareTo(a) ? this : a;
  };
  b.prototype.max = function (a) {
    return 0 < this.compareTo(a) ? this : a;
  };
  b.prototype.and = function (a) {
    var e = h();
    this.bitwiseTo(a, f, e);
    return e;
  };
  b.prototype.or = function (a) {
    var e = h();
    this.bitwiseTo(a, F, e);
    return e;
  };
  b.prototype.xor = function (a) {
    var e = h();
    this.bitwiseTo(a, G, e);
    return e;
  };
  b.prototype.andNot = function (a) {
    var e = h();
    this.bitwiseTo(a, I, e);
    return e;
  };
  b.prototype.not = function () {
    for (var a = h(), e = 0; e < this.t; ++e) a[e] = this.DM & ~this[e];
    a.t = this.t;
    a.s = ~this.s;
    return a;
  };
  b.prototype.shiftLeft = function (a) {
    var e = h();
    0 > a ? this.rShiftTo(-a, e) : this.lShiftTo(a, e);
    return e;
  };
  b.prototype.shiftRight = function (a) {
    var e = h();
    0 > a ? this.lShiftTo(-a, e) : this.rShiftTo(a, e);
    return e;
  };
  b.prototype.getLowestSetBit = function () {
    for (var a = 0; a < this.t; ++a)
      if (0 != this[a]) {
        var e = a * this.DB;
        a = this[a];
        if (0 == a) a = -1;
        else {
          var b = 0;
          0 == (a & 65535) && ((a >>= 16), (b += 16));
          0 == (a & 255) && ((a >>= 8), (b += 8));
          0 == (a & 15) && ((a >>= 4), (b += 4));
          0 == (a & 3) && ((a >>= 2), (b += 2));
          0 == (a & 1) && ++b;
          a = b;
        }
        return e + a;
      }
    return 0 > this.s ? this.t * this.DB : -1;
  };
  b.prototype.bitCount = function () {
    for (var a = 0, b = this.s & this.DM, g = 0; g < this.t; ++g) {
      for (var c = this[g] ^ b, l = 0; 0 != c; ) (c &= c - 1), ++l;
      a += l;
    }
    return a;
  };
  b.prototype.testBit = function (a) {
    var b = Math.floor(a / this.DB);
    return b >= this.t ? 0 != this.s : 0 != (this[b] & (1 << a % this.DB));
  };
  b.prototype.setBit = function (a) {
    return this.changeBit(a, F);
  };
  b.prototype.clearBit = function (a) {
    return this.changeBit(a, I);
  };
  b.prototype.flipBit = function (a) {
    return this.changeBit(a, G);
  };
  b.prototype.add = function (a) {
    var b = h();
    this.addTo(a, b);
    return b;
  };
  b.prototype.subtract = function (a) {
    var b = h();
    this.subTo(a, b);
    return b;
  };
  b.prototype.multiply = function (a) {
    var b = h();
    this.multiplyTo(a, b);
    return b;
  };
  b.prototype.divide = function (a) {
    var b = h();
    this.divRemTo(a, b, null);
    return b;
  };
  b.prototype.remainder = function (a) {
    var b = h();
    this.divRemTo(a, null, b);
    return b;
  };
  b.prototype.divideAndRemainder = function (a) {
    var b = h(),
      g = h();
    this.divRemTo(a, b, g);
    return [b, g];
  };
  b.prototype.modPow = function (a, b) {
    var g = a.bitLength(),
      c,
      l = A(1),
      d;
    if (0 >= g) return l;
    c = 18 > g ? 1 : 48 > g ? 3 : 144 > g ? 4 : 768 > g ? 5 : 6;
    d = 8 > g ? new C(b) : b.isEven() ? new t(b) : new D(b);
    var q = [],
      f = 3,
      k = c - 1,
      r = (1 << c) - 1;
    q[1] = d.convert(this);
    if (1 < c)
      for (g = h(), d.sqrTo(q[1], g); f <= r; )
        (q[f] = h()), d.mulTo(g, q[f - 2], q[f]), (f += 2);
    for (var m = a.t - 1, n, p = !0, u = h(), g = z(a[m]) - 1; 0 <= m; ) {
      g >= k
        ? (n = (a[m] >> (g - k)) & r)
        : ((n = (a[m] & ((1 << (g + 1)) - 1)) << (k - g)),
          0 < m && (n |= a[m - 1] >> (this.DB + g - k)));
      for (f = c; 0 == (n & 1); ) (n >>= 1), --f;
      0 > (g -= f) && ((g += this.DB), --m);
      if (p) q[n].copyTo(l), (p = !1);
      else {
        for (; 1 < f; ) d.sqrTo(l, u), d.sqrTo(u, l), (f -= 2);
        0 < f ? d.sqrTo(l, u) : ((f = l), (l = u), (u = f));
        d.mulTo(u, q[n], l);
      }
      for (; 0 <= m && 0 == (a[m] & (1 << g)); )
        d.sqrTo(l, u),
          (f = l),
          (l = u),
          (u = f),
          0 > --g && ((g = this.DB - 1), --m);
    }
    return d.revert(l);
  };
  b.prototype.modInverse = function (a) {
    var e = a.isEven();
    if ((this.isEven() && e) || 0 == a.signum()) return b.ZERO;
    for (
      var g = a.clone(),
        c = this.clone(),
        l = A(1),
        d = A(0),
        q = A(0),
        f = A(1);
      0 != g.signum();

    ) {
      for (; g.isEven(); )
        g.rShiftTo(1, g),
          e
            ? ((l.isEven() && d.isEven()) || (l.addTo(this, l), d.subTo(a, d)),
              l.rShiftTo(1, l))
            : d.isEven() || d.subTo(a, d),
          d.rShiftTo(1, d);
      for (; c.isEven(); )
        c.rShiftTo(1, c),
          e
            ? ((q.isEven() && f.isEven()) || (q.addTo(this, q), f.subTo(a, f)),
              q.rShiftTo(1, q))
            : f.isEven() || f.subTo(a, f),
          f.rShiftTo(1, f);
      0 <= g.compareTo(c)
        ? (g.subTo(c, g), e && l.subTo(q, l), d.subTo(f, d))
        : (c.subTo(g, c), e && q.subTo(l, q), f.subTo(d, f));
    }
    if (0 != c.compareTo(b.ONE)) return b.ZERO;
    if (0 <= f.compareTo(a)) return f.subtract(a);
    if (0 > f.signum()) f.addTo(a, f);
    else return f;
    return 0 > f.signum() ? f.add(a) : f;
  };
  b.prototype.pow = function (a) {
    return this.exp(a, new d());
  };
  b.prototype.gcd = function (a) {
    var b = 0 > this.s ? this.negate() : this.clone();
    a = 0 > a.s ? a.negate() : a.clone();
    if (0 > b.compareTo(a)) {
      var g = b,
        b = a;
      a = g;
    }
    var g = b.getLowestSetBit(),
      c = a.getLowestSetBit();
    if (0 > c) return b;
    g < c && (c = g);
    0 < c && (b.rShiftTo(c, b), a.rShiftTo(c, a));
    for (; 0 < b.signum(); )
      0 < (g = b.getLowestSetBit()) && b.rShiftTo(g, b),
        0 < (g = a.getLowestSetBit()) && a.rShiftTo(g, a),
        0 <= b.compareTo(a)
          ? (b.subTo(a, b), b.rShiftTo(1, b))
          : (a.subTo(b, a), a.rShiftTo(1, a));
    0 < c && a.lShiftTo(c, a);
    return a;
  };
  b.prototype.isProbablePrime = function (a) {
    var b,
      g = this.abs();
    if (1 == g.t && g[0] <= N[N.length - 1]) {
      for (b = 0; b < N.length; ++b) if (g[0] == N[b]) return !0;
      return !1;
    }
    if (g.isEven()) return !1;
    for (b = 1; b < N.length; ) {
      for (var c = N[b], l = b + 1; l < N.length && c < S; ) c *= N[l++];
      for (c = g.modInt(c); b < l; ) if (0 == c % N[b++]) return !1;
    }
    return g.millerRabin(a);
  };
  b.prototype.square = function () {
    var a = h();
    this.squareTo(a);
    return a;
  };
  p.prototype.init = function (a) {
    var b, g, c;
    for (b = 0; 256 > b; ++b) this.S[b] = b;
    for (b = g = 0; 256 > b; ++b)
      (g = (g + this.S[b] + a[b % a.length]) & 255),
        (c = this.S[b]),
        (this.S[b] = this.S[g]),
        (this.S[g] = c);
    this.j = this.i = 0;
  };
  p.prototype.next = function () {
    var a;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    a = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = a;
    return this.S[(a + this.S[this.i]) & 255];
  };
  var Q, P, O;
  if (null == P) {
    P = [];
    O = 0;
    if (window.crypto && window.crypto.getRandomValues)
      for (
        K = new Uint32Array(256), window.crypto.getRandomValues(K), M = 0;
        M < K.length;
        ++M
      )
        P[O++] = K[M] & 255;
    var u = function (a) {
      this.count = this.count || 0;
      if (256 <= this.count || 256 <= O)
        window.removeEventListener
          ? window.removeEventListener("mousemove", u, !1)
          : window.detachEvent && window.detachEvent("onmousemove", u);
      else
        try {
          var b = a.x + a.y;
          P[O++] = b & 255;
          this.count += 1;
        } catch (g) {}
    };
    window.addEventListener
      ? window.addEventListener("mousemove", u, !1)
      : window.attachEvent && window.attachEvent("onmousemove", u);
  }
  B.prototype.nextBytes = function (a) {
    var b;
    for (b = 0; b < a.length; ++b) {
      var g = b,
        c;
      if (null == Q) {
        for (Q = new p(); 256 > O; )
          (c = Math.floor(65536 * Math.random())), (P[O++] = c & 255);
        Q.init(P);
        for (O = 0; O < P.length; ++O) P[O] = 0;
        O = 0;
      }
      c = Q.next();
      a[g] = c;
    }
  };
  H.prototype.doPublic = function (a) {
    return a.modPowInt(this.e, this.n);
  };
  H.prototype.setPublic = function (a, b) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = E(a, 16)), (this.e = parseInt(b, 16)))
      : console.error("Invalid RSA public key");
  };
  H.prototype.encrypt = function (a) {
    var e;
    e = (this.n.bitLength() + 7) >> 3;
    if (e < a.length + 11)
      console.error("Message too long for RSA"), (e = null);
    else {
      for (var g = [], c = a.length - 1; 0 <= c && 0 < e; ) {
        var l = a.charCodeAt(c--);
        128 > l
          ? (g[--e] = l)
          : 127 < l && 2048 > l
          ? ((g[--e] = (l & 63) | 128), (g[--e] = (l >> 6) | 192))
          : ((g[--e] = (l & 63) | 128),
            (g[--e] = ((l >> 6) & 63) | 128),
            (g[--e] = (l >> 12) | 224));
      }
      g[--e] = 0;
      a = new B();
      for (c = []; 2 < e; ) {
        for (c[0] = 0; 0 == c[0]; ) a.nextBytes(c);
        g[--e] = c[0];
      }
      g[--e] = 2;
      g[--e] = 0;
      e = new b(g);
    }
    if (null == e) return null;
    e = this.doPublic(e);
    if (null == e) return null;
    e = e.toString(16);
    return 0 == (e.length & 1) ? e : "0" + e;
  };
  H.prototype.doPrivate = function (a) {
    if (null == this.p || null == this.q) return a.modPow(this.d, this.n);
    var b = a.mod(this.p).modPow(this.dmp1, this.p);
    for (a = a.mod(this.q).modPow(this.dmq1, this.q); 0 > b.compareTo(a); )
      b = b.add(this.p);
    return b
      .subtract(a)
      .multiply(this.coeff)
      .mod(this.p)
      .multiply(this.q)
      .add(a);
  };
  H.prototype.setPrivate = function (a, b, c) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = E(a, 16)), (this.e = parseInt(b, 16)), (this.d = E(c, 16)))
      : console.error("Invalid RSA private key");
  };
  H.prototype.setPrivateEx = function (a, b, c, d, l, f, q, h) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = E(a, 16)),
        (this.e = parseInt(b, 16)),
        (this.d = E(c, 16)),
        (this.p = E(d, 16)),
        (this.q = E(l, 16)),
        (this.dmp1 = E(f, 16)),
        (this.dmq1 = E(q, 16)),
        (this.coeff = E(h, 16)))
      : console.error("Invalid RSA private key");
  };
  H.prototype.generate = function (a, e) {
    var c = new B(),
      d = a >> 1;
    this.e = parseInt(e, 16);
    for (var l = new b(e, 16); ; ) {
      for (
        ;
        (this.p = new b(a - d, 1, c)),
          0 != this.p.subtract(b.ONE).gcd(l).compareTo(b.ONE) ||
            !this.p.isProbablePrime(10);

      );
      for (
        ;
        (this.q = new b(d, 1, c)),
          0 != this.q.subtract(b.ONE).gcd(l).compareTo(b.ONE) ||
            !this.q.isProbablePrime(10);

      );
      if (0 >= this.p.compareTo(this.q)) {
        var f = this.p;
        this.p = this.q;
        this.q = f;
      }
      var f = this.p.subtract(b.ONE),
        q = this.q.subtract(b.ONE),
        h = f.multiply(q);
      if (0 == h.gcd(l).compareTo(b.ONE)) {
        this.n = this.p.multiply(this.q);
        this.d = l.modInverse(h);
        this.dmp1 = this.d.mod(f);
        this.dmq1 = this.d.mod(q);
        this.coeff = this.q.modInverse(this.p);
        break;
      }
    }
  };
  H.prototype.decrypt = function (a) {
    a = E(a, 16);
    a = this.doPrivate(a);
    if (null == a) return null;
    a: {
      var b = (this.n.bitLength() + 7) >> 3;
      a = a.toByteArray();
      for (var c = 0; c < a.length && 0 == a[c]; ) ++c;
      if (a.length - c != b - 1 || 2 != a[c]) a = null;
      else {
        for (++c; 0 != a[c]; )
          if (++c >= a.length) {
            a = null;
            break a;
          }
        for (b = ""; ++c < a.length; ) {
          var d = a[c] & 255;
          128 > d
            ? (b += String.fromCharCode(d))
            : 191 < d && 224 > d
            ? ((b += String.fromCharCode(((d & 31) << 6) | (a[c + 1] & 63))),
              ++c)
            : ((b += String.fromCharCode(
                ((d & 15) << 12) | ((a[c + 1] & 63) << 6) | (a[c + 2] & 63)
              )),
              (c += 2));
        }
        a = b;
      }
    }
    return a;
  };
  (function () {
    H.prototype.generateAsync = function (a, c, g) {
      var d = new B(),
        l = a >> 1;
      this.e = parseInt(c, 16);
      var f = new b(c, 16),
        q = this,
        X = function () {
          var c = function () {
              if (0 >= q.p.compareTo(q.q)) {
                var a = q.p;
                q.p = q.q;
                q.q = a;
              }
              var a = q.p.subtract(b.ONE),
                c = q.q.subtract(b.ONE),
                e = a.multiply(c);
              0 == e.gcd(f).compareTo(b.ONE)
                ? ((q.n = q.p.multiply(q.q)),
                  (q.d = f.modInverse(e)),
                  (q.dmp1 = q.d.mod(a)),
                  (q.dmq1 = q.d.mod(c)),
                  (q.coeff = q.q.modInverse(q.p)),
                  setTimeout(function () {
                    g();
                  }, 0))
                : setTimeout(X, 0);
            },
            e = function () {
              q.q = h();
              q.q.fromNumberAsync(l, 1, d, function () {
                q.q.subtract(b.ONE).gcda(f, function (a) {
                  0 == a.compareTo(b.ONE) && q.q.isProbablePrime(10)
                    ? setTimeout(c, 0)
                    : setTimeout(e, 0);
                });
              });
            },
            k = function () {
              q.p = h();
              q.p.fromNumberAsync(a - l, 1, d, function () {
                q.p.subtract(b.ONE).gcda(f, function (a) {
                  0 == a.compareTo(b.ONE) && q.p.isProbablePrime(10)
                    ? setTimeout(e, 0)
                    : setTimeout(k, 0);
                });
              });
            };
          setTimeout(k, 0);
        };
      setTimeout(X, 0);
    };
    b.prototype.gcda = function (a, b) {
      var c = 0 > this.s ? this.negate() : this.clone(),
        d = 0 > a.s ? a.negate() : a.clone();
      if (0 > c.compareTo(d))
        var l = c,
          c = d,
          d = l;
      var f = c.getLowestSetBit(),
        q = d.getLowestSetBit();
      if (0 > q) b(c);
      else {
        f < q && (q = f);
        0 < q && (c.rShiftTo(q, c), d.rShiftTo(q, d));
        var h = function () {
          0 < (f = c.getLowestSetBit()) && c.rShiftTo(f, c);
          0 < (f = d.getLowestSetBit()) && d.rShiftTo(f, d);
          0 <= c.compareTo(d)
            ? (c.subTo(d, c), c.rShiftTo(1, c))
            : (d.subTo(c, d), d.rShiftTo(1, d));
          0 < c.signum()
            ? setTimeout(h, 0)
            : (0 < q && d.lShiftTo(q, d),
              setTimeout(function () {
                b(d);
              }, 0));
        };
        setTimeout(h, 10);
      }
    };
    b.prototype.fromNumberAsync = function (a, c, g, d) {
      if ("number" == typeof c)
        if (2 > a) this.fromInt(1);
        else {
          this.fromNumber(a, g);
          this.testBit(a - 1) ||
            this.bitwiseTo(b.ONE.shiftLeft(a - 1), F, this);
          this.isEven() && this.dAddOffset(1, 0);
          var l = this,
            f = function () {
              l.dAddOffset(2, 0);
              l.bitLength() > a && l.subTo(b.ONE.shiftLeft(a - 1), l);
              l.isProbablePrime(c)
                ? setTimeout(function () {
                    d();
                  }, 0)
                : setTimeout(f, 0);
            };
          setTimeout(f, 0);
        }
      else {
        g = [];
        var q = a & 7;
        g.length = (a >> 3) + 1;
        c.nextBytes(g);
        g[0] = 0 < q ? g[0] & ((1 << q) - 1) : 0;
        this.fromString(g, 256);
      }
    };
  })();
  var k = k || {};
  k.env = k.env || {};
  var w = k,
    x = Object.prototype,
    W = ["toString", "valueOf"];
  k.env.parseUA = function (a) {
    var b = function (a) {
        var b = 0;
        return parseFloat(
          a.replace(/\./g, function () {
            return 1 == b++ ? "" : ".";
          })
        );
      },
      c = navigator,
      c = {
        ie: 0,
        opera: 0,
        gecko: 0,
        webkit: 0,
        chrome: 0,
        mobile: null,
        air: 0,
        ipad: 0,
        iphone: 0,
        ipod: 0,
        ios: null,
        android: 0,
        webos: 0,
        caja: c && c.cajaVersion,
        secure: !1,
        os: null,
      };
    a = a || (navigator && navigator.userAgent);
    var d = window && window.location,
      d = d && d.href;
    c.secure = d && 0 === d.toLowerCase().indexOf("https");
    if (a) {
      /windows|win32/i.test(a)
        ? (c.os = "windows")
        : /macintosh/i.test(a)
        ? (c.os = "macintosh")
        : /rhino/i.test(a) && (c.os = "rhino");
      /KHTML/.test(a) && (c.webkit = 1);
      if ((d = a.match(/AppleWebKit\/([^\s]*)/)) && d[1]) {
        c.webkit = b(d[1]);
        if (/ Mobile\//.test(a))
          (c.mobile = "Apple"),
            (d = a.match(/OS ([^\s]*)/)) &&
              d[1] &&
              (d = b(d[1].replace("_", "."))),
            (c.ios = d),
            (c.ipad = c.ipod = c.iphone = 0),
            (d = a.match(/iPad|iPod|iPhone/)) &&
              d[0] &&
              (c[d[0].toLowerCase()] = c.ios);
        else {
          if ((d = a.match(/NokiaN[^\/]*|Android \d\.\d|webOS\/\d\.\d/)))
            c.mobile = d[0];
          /webOS/.test(a) &&
            ((c.mobile = "WebOS"),
            (d = a.match(/webOS\/([^\s]*);/)) && d[1] && (c.webos = b(d[1])));
          / Android/.test(a) &&
            ((c.mobile = "Android"),
            (d = a.match(/Android ([^\s]*);/)) &&
              d[1] &&
              (c.android = b(d[1])));
        }
        if ((d = a.match(/Chrome\/([^\s]*)/)) && d[1]) c.chrome = b(d[1]);
        else if ((d = a.match(/AdobeAIR\/([^\s]*)/))) c.air = d[0];
      }
      if (!c.webkit)
        if ((d = a.match(/Opera[\s\/]([^\s]*)/)) && d[1]) {
          if (
            ((c.opera = b(d[1])),
            (d = a.match(/Version\/([^\s]*)/)) && d[1] && (c.opera = b(d[1])),
            (d = a.match(/Opera Mini[^;]*/)))
          )
            c.mobile = d[0];
        } else if ((d = a.match(/MSIE\s([^;]*)/)) && d[1]) c.ie = b(d[1]);
        else if ((d = a.match(/Gecko\/([^\s]*)/)))
          (c.gecko = 1),
            (d = a.match(/rv:([^\s\)]*)/)) && d[1] && (c.gecko = b(d[1]));
    }
    return c;
  };
  k.env.ua = k.env.parseUA();
  k.isFunction = function (a) {
    return (
      "function" === typeof a || "[object Function]" === x.toString.apply(a)
    );
  };
  k._IEEnumFix = k.env.ua.ie
    ? function (a, b) {
        var c, d, l;
        for (c = 0; c < W.length; c += 1)
          (d = W[c]), (l = b[d]), w.isFunction(l) && l != x[d] && (a[d] = l);
      }
    : function () {};
  k.extend = function (a, b, c) {
    if (!b || !a)
      throw Error(
        "extend failed, please check that all dependencies are included."
      );
    var d = function () {},
      l;
    d.prototype = b.prototype;
    a.prototype = new d();
    a.prototype.constructor = a;
    a.superclass = b.prototype;
    b.prototype.constructor == x.constructor && (b.prototype.constructor = b);
    if (c) {
      for (l in c) w.hasOwnProperty(c, l) && (a.prototype[l] = c[l]);
      w._IEEnumFix(a.prototype, c);
    }
  };
  ("undefined" != typeof KJUR && KJUR) || (KJUR = {});
  ("undefined" != typeof KJUR.asn1 && KJUR.asn1) || (KJUR.asn1 = {});
  KJUR.asn1.ASN1Util = new (function () {
    this.integerToByteHex = function (a) {
      a = a.toString(16);
      1 == a.length % 2 && (a = "0" + a);
      return a;
    };
    this.bigIntToMinTwosComplementsHex = function (a) {
      var c = a.toString(16);
      if ("-" != c.substr(0, 1))
        1 == c.length % 2 ? (c = "0" + c) : c.match(/^[0-7]/) || (c = "00" + c);
      else {
        var d = c.substr(1).length;
        1 == d % 2 ? (d += 1) : c.match(/^[0-7]/) || (d += 2);
        for (var c = "", f = 0; f < d; f++) c += "f";
        c = new b(c, 16).xor(a).add(b.ONE).toString(16).replace(/^-/, "");
      }
      return c;
    };
    this.getPEMStringFromHex = function (a, b) {
      var c = CryptoJS.enc.Hex.parse(a),
        c = CryptoJS.enc.Base64.stringify(c).replace(/(.{64})/g, "$1\r\n"),
        c = c.replace(/\r\n$/, "");
      return (
        "-----BEGIN " + b + "-----\r\n" + c + "\r\n-----END " + b + "-----\r\n"
      );
    };
  })();
  KJUR.asn1.ASN1Object = function () {
    this.getLengthHexFromValue = function () {
      if ("undefined" == typeof this.hV || null == this.hV)
        throw "this.hV is null or undefined.";
      if (1 == this.hV.length % 2)
        throw "value hex must be even length: n=0,v=" + this.hV;
      var a = this.hV.length / 2,
        b = a.toString(16);
      1 == b.length % 2 && (b = "0" + b);
      if (128 > a) return b;
      var c = b.length / 2;
      if (15 < c)
        throw "ASN.1 length too long to represent by 8x: n = " + a.toString(16);
      return (128 + c).toString(16) + b;
    };
    this.getEncodedHex = function () {
      if (null == this.hTLV || this.isModified)
        (this.hV = this.getFreshValueHex()),
          (this.hL = this.getLengthHexFromValue()),
          (this.hTLV = this.hT + this.hL + this.hV),
          (this.isModified = !1);
      return this.hTLV;
    };
    this.getValueHex = function () {
      this.getEncodedHex();
      return this.hV;
    };
    this.getFreshValueHex = function () {
      return "";
    };
  };
  KJUR.asn1.DERAbstractString = function (a) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    this.getString = function () {
      return this.s;
    };
    this.setString = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.s = a;
      this.hV = stohex(this.s);
    };
    this.setStringHex = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.s = null;
      this.hV = a;
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.str
        ? this.setString(a.str)
        : "undefined" != typeof a.hex && this.setStringHex(a.hex));
  };
  k.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERAbstractTime = function (a) {
    KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
    this.localDateToUTC = function (a) {
      utc = a.getTime() + 6e4 * a.getTimezoneOffset();
      return new Date(utc);
    };
    this.formatDate = function (a, b) {
      var c = this.zeroPadding,
        d = this.localDateToUTC(a),
        f = String(d.getFullYear());
      "utc" == b && (f = f.substr(2, 2));
      var q = c(String(d.getMonth() + 1), 2),
        h = c(String(d.getDate()), 2),
        k = c(String(d.getHours()), 2),
        m = c(String(d.getMinutes()), 2),
        c = c(String(d.getSeconds()), 2);
      return f + q + h + k + m + c + "Z";
    };
    this.zeroPadding = function (a, b) {
      return a.length >= b ? a : Array(b - a.length + 1).join("0") + a;
    };
    this.getString = function () {
      return this.s;
    };
    this.setString = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.s = a;
      this.hV = stohex(this.s);
    };
    this.setByDateValue = function (a, b, c, d, f, q) {
      a = new Date(Date.UTC(a, b - 1, c, d, f, q, 0));
      this.setByDate(a);
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
  };
  k.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERAbstractStructured = function (a) {
    KJUR.asn1.DERAbstractString.superclass.constructor.call(this);
    this.setByASN1ObjectArray = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.asn1Array = a;
    };
    this.appendASN1Object = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.asn1Array.push(a);
    };
    this.asn1Array = [];
    "undefined" != typeof a &&
      "undefined" != typeof a.array &&
      (this.asn1Array = a.array);
  };
  k.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERBoolean = function () {
    KJUR.asn1.DERBoolean.superclass.constructor.call(this);
    this.hT = "01";
    this.hTLV = "0101ff";
  };
  k.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERInteger = function (a) {
    KJUR.asn1.DERInteger.superclass.constructor.call(this);
    this.hT = "02";
    this.setByBigInteger = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.hV = KJUR.asn1.ASN1Util.bigIntToMinTwosComplementsHex(a);
    };
    this.setByInteger = function (a) {
      a = new b(String(a), 10);
      this.setByBigInteger(a);
    };
    this.setValueHex = function (a) {
      this.hV = a;
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.bigint
        ? this.setByBigInteger(a.bigint)
        : "undefined" != typeof a["int"]
        ? this.setByInteger(a["int"])
        : "undefined" != typeof a.hex && this.setValueHex(a.hex));
  };
  k.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERBitString = function (a) {
    KJUR.asn1.DERBitString.superclass.constructor.call(this);
    this.hT = "03";
    this.setHexValueIncludingUnusedBits = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.hV = a;
    };
    this.setUnusedBitsAndHexValue = function (a, b) {
      if (0 > a || 7 < a) throw "unused bits shall be from 0 to 7: u = " + a;
      this.hTLV = null;
      this.isModified = !0;
      this.hV = "0" + a + b;
    };
    this.setByBinaryString = function (a) {
      a = a.replace(/0+$/, "");
      var b = 8 - (a.length % 8);
      8 == b && (b = 0);
      for (var c = 0; c <= b; c++) a += "0";
      for (var d = "", c = 0; c < a.length - 1; c += 8) {
        var f = a.substr(c, 8),
          f = parseInt(f, 2).toString(16);
        1 == f.length && (f = "0" + f);
        d += f;
      }
      this.hTLV = null;
      this.isModified = !0;
      this.hV = "0" + b + d;
    };
    this.setByBooleanArray = function (a) {
      for (var b = "", c = 0; c < a.length; c++)
        b = 1 == a[c] ? b + "1" : b + "0";
      this.setByBinaryString(b);
    };
    this.newFalseArray = function (a) {
      for (var b = Array(a), c = 0; c < a; c++) b[c] = !1;
      return b;
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.hex
        ? this.setHexValueIncludingUnusedBits(a.hex)
        : "undefined" != typeof a.bin
        ? this.setByBinaryString(a.bin)
        : "undefined" != typeof a.array && this.setByBooleanArray(a.array));
  };
  k.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);
  KJUR.asn1.DEROctetString = function (a) {
    KJUR.asn1.DEROctetString.superclass.constructor.call(this, a);
    this.hT = "04";
  };
  k.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERNull = function () {
    KJUR.asn1.DERNull.superclass.constructor.call(this);
    this.hT = "05";
    this.hTLV = "0500";
  };
  k.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERObjectIdentifier = function (a) {
    var c = function (a) {
      a = a.toString(16);
      1 == a.length && (a = "0" + a);
      return a;
    };
    KJUR.asn1.DERObjectIdentifier.superclass.constructor.call(this);
    this.hT = "06";
    this.setValueHex = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.s = null;
      this.hV = a;
    };
    this.setValueOidString = function (a) {
      if (!a.match(/^[0-9.]+$/)) throw "malformed oid string: " + a;
      var d = "";
      a = a.split(".");
      var l = 40 * parseInt(a[0]) + parseInt(a[1]),
        d = d + c(l);
      a.splice(0, 2);
      for (l = 0; l < a.length; l++) {
        var f = "",
          q = new b(a[l], 10).toString(2),
          h = 7 - (q.length % 7);
        7 == h && (h = 0);
        for (var k = "", m = 0; m < h; m++) k += "0";
        q = k + q;
        for (m = 0; m < q.length - 1; m += 7)
          (h = q.substr(m, 7)),
            m != q.length - 7 && (h = "1" + h),
            (f += c(parseInt(h, 2)));
        d += f;
      }
      this.hTLV = null;
      this.isModified = !0;
      this.s = null;
      this.hV = d;
    };
    this.setValueName = function (a) {
      if ("undefined" != typeof KJUR.asn1.x509.OID.name2oidList[a])
        this.setValueOidString(KJUR.asn1.x509.OID.name2oidList[a]);
      else throw "DERObjectIdentifier oidName undefined: " + a;
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.oid
        ? this.setValueOidString(a.oid)
        : "undefined" != typeof a.hex
        ? this.setValueHex(a.hex)
        : "undefined" != typeof a.name && this.setValueName(a.name));
  };
  k.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERUTF8String = function (a) {
    KJUR.asn1.DERUTF8String.superclass.constructor.call(this, a);
    this.hT = "0c";
  };
  k.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERNumericString = function (a) {
    KJUR.asn1.DERNumericString.superclass.constructor.call(this, a);
    this.hT = "12";
  };
  k.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERPrintableString = function (a) {
    KJUR.asn1.DERPrintableString.superclass.constructor.call(this, a);
    this.hT = "13";
  };
  k.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERTeletexString = function (a) {
    KJUR.asn1.DERTeletexString.superclass.constructor.call(this, a);
    this.hT = "14";
  };
  k.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERIA5String = function (a) {
    KJUR.asn1.DERIA5String.superclass.constructor.call(this, a);
    this.hT = "16";
  };
  k.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERUTCTime = function (a) {
    KJUR.asn1.DERUTCTime.superclass.constructor.call(this, a);
    this.hT = "17";
    this.setByDate = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.date = a;
      this.s = this.formatDate(this.date, "utc");
      this.hV = stohex(this.s);
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.str
        ? this.setString(a.str)
        : "undefined" != typeof a.hex
        ? this.setStringHex(a.hex)
        : "undefined" != typeof a.date && this.setByDate(a.date));
  };
  k.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);
  KJUR.asn1.DERGeneralizedTime = function (a) {
    KJUR.asn1.DERGeneralizedTime.superclass.constructor.call(this, a);
    this.hT = "18";
    this.setByDate = function (a) {
      this.hTLV = null;
      this.isModified = !0;
      this.date = a;
      this.s = this.formatDate(this.date, "gen");
      this.hV = stohex(this.s);
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.str
        ? this.setString(a.str)
        : "undefined" != typeof a.hex
        ? this.setStringHex(a.hex)
        : "undefined" != typeof a.date && this.setByDate(a.date));
  };
  k.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);
  KJUR.asn1.DERSequence = function (a) {
    KJUR.asn1.DERSequence.superclass.constructor.call(this, a);
    this.hT = "30";
    this.getFreshValueHex = function () {
      for (var a = "", b = 0; b < this.asn1Array.length; b++)
        a += this.asn1Array[b].getEncodedHex();
      return (this.hV = a);
    };
  };
  k.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);
  KJUR.asn1.DERSet = function (a) {
    KJUR.asn1.DERSet.superclass.constructor.call(this, a);
    this.hT = "31";
    this.getFreshValueHex = function () {
      for (var a = [], b = 0; b < this.asn1Array.length; b++)
        a.push(this.asn1Array[b].getEncodedHex());
      a.sort();
      return (this.hV = a.join(""));
    };
  };
  k.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);
  KJUR.asn1.DERTaggedObject = function (a) {
    KJUR.asn1.DERTaggedObject.superclass.constructor.call(this);
    this.hT = "a0";
    this.hV = "";
    this.isExplicit = !0;
    this.asn1Object = null;
    this.setASN1Object = function (a, b, c) {
      this.hT = b;
      this.isExplicit = a;
      this.asn1Object = c;
      this.isExplicit
        ? ((this.hV = this.asn1Object.getEncodedHex()),
          (this.hTLV = null),
          (this.isModified = !0))
        : ((this.hV = null),
          (this.hTLV = c.getEncodedHex()),
          (this.hTLV = this.hTLV.replace(/^../, b)),
          (this.isModified = !1));
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
    "undefined" != typeof a &&
      ("undefined" != typeof a.tag && (this.hT = a.tag),
      "undefined" != typeof a.explicit && (this.isExplicit = a.explicit),
      "undefined" != typeof a.obj &&
        ((this.asn1Object = a.obj),
        this.setASN1Object(this.isExplicit, this.hT, this.asn1Object)));
  };
  k.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);
  (function (a) {
    var b = {},
      c;
    b.decode = function (b) {
      var d;
      if (c === a) {
        var e = "0123456789ABCDEF";
        c = [];
        for (d = 0; 16 > d; ++d) c[e.charAt(d)] = d;
        e = e.toLowerCase();
        for (d = 10; 16 > d; ++d) c[e.charAt(d)] = d;
        for (d = 0; 8 > d; ++d) c[" \f\n\r\tÂ \u2028\u2029".charAt(d)] = -1;
      }
      var e = [],
        f = 0,
        h = 0;
      for (d = 0; d < b.length; ++d) {
        var k = b.charAt(d);
        if ("=" == k) break;
        k = c[k];
        if (-1 != k) {
          if (k === a) throw "Illegal character at offset " + d;
          f |= k;
          2 <= ++h ? ((e[e.length] = f), (h = f = 0)) : (f <<= 4);
        }
      }
      if (h) throw "Hex encoding incomplete: 4 bits missing";
      return e;
    };
    window.Hex = b;
  })();
  (function (a) {
    var b = {},
      c;
    b.decode = function (b) {
      var d;
      if (c === a) {
        c = [];
        for (d = 0; 64 > d; ++d)
          c[
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
              d
            )
          ] = d;
        for (d = 0; 9 > d; ++d) c["= \f\n\r\tÂ \u2028\u2029".charAt(d)] = -1;
      }
      var e = [],
        f = 0,
        h = 0;
      for (d = 0; d < b.length; ++d) {
        var k = b.charAt(d);
        if ("=" == k) break;
        k = c[k];
        if (-1 != k) {
          if (k === a) throw "Illegal character at offset " + d;
          f |= k;
          4 <= ++h
            ? ((e[e.length] = f >> 16),
              (e[e.length] = (f >> 8) & 255),
              (e[e.length] = f & 255),
              (h = f = 0))
            : (f <<= 6);
        }
      }
      switch (h) {
        case 1:
          throw "Base64 encoding incomplete: at least 2 bits missing";
        case 2:
          e[e.length] = f >> 10;
          break;
        case 3:
          (e[e.length] = f >> 16), (e[e.length] = (f >> 8) & 255);
      }
      return e;
    };
    b.re =
      /-----BEGIN [^-]+-----([A-Za-z0-9+\/=\s]+)-----END [^-]+-----|begin-base64[^\n]+\n([A-Za-z0-9+\/=\s]+)====/;
    b.unarmor = function (a) {
      var c = b.re.exec(a);
      if (c)
        if (c[1]) a = c[1];
        else if (c[2]) a = c[2];
        else throw "RegExp out of sync";
      return b.decode(a);
    };
    window.Base64 = b;
  })();
  (function (a) {
    function b(a, c) {
      a instanceof b
        ? ((this.enc = a.enc), (this.pos = a.pos))
        : ((this.enc = a), (this.pos = c));
    }
    function c(a, b, d, e, f) {
      this.stream = a;
      this.header = b;
      this.length = d;
      this.tag = e;
      this.sub = f;
    }
    var d = {
      tag: function (a, b) {
        var c = document.createElement(a);
        c.className = b;
        return c;
      },
      text: function (a) {
        return document.createTextNode(a);
      },
    };
    b.prototype.get = function (b) {
      b === a && (b = this.pos++);
      if (b >= this.enc.length)
        throw (
          "Requesting byte offset " +
          b +
          " on a stream of length " +
          this.enc.length
        );
      return this.enc[b];
    };
    b.prototype.hexDigits = "0123456789ABCDEF";
    b.prototype.hexByte = function (a) {
      return (
        this.hexDigits.charAt((a >> 4) & 15) + this.hexDigits.charAt(a & 15)
      );
    };
    b.prototype.hexDump = function (a, b, c) {
      for (var d = ""; a < b; ++a)
        if (((d += this.hexByte(this.get(a))), !0 !== c))
          switch (a & 15) {
            case 7:
              d += "  ";
              break;
            case 15:
              d += "\n";
              break;
            default:
              d += " ";
          }
      return d;
    };
    b.prototype.parseStringISO = function (a, b) {
      for (var c = "", d = a; d < b; ++d) c += String.fromCharCode(this.get(d));
      return c;
    };
    b.prototype.parseStringUTF = function (a, b) {
      for (var c = "", d = a; d < b; )
        var e = this.get(d++),
          c =
            128 > e
              ? c + String.fromCharCode(e)
              : 191 < e && 224 > e
              ? c + String.fromCharCode(((e & 31) << 6) | (this.get(d++) & 63))
              : c +
                String.fromCharCode(
                  ((e & 15) << 12) |
                    ((this.get(d++) & 63) << 6) |
                    (this.get(d++) & 63)
                );
      return c;
    };
    b.prototype.parseStringBMP = function (a, b) {
      for (var c = "", d = a; d < b; d += 2)
        var e = this.get(d),
          f = this.get(d + 1),
          c = c + String.fromCharCode((e << 8) + f);
      return c;
    };
    b.prototype.reTime =
      /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
    b.prototype.parseTime = function (a, b) {
      var c = this.parseStringISO(a, b),
        d = this.reTime.exec(c);
      if (!d) return "Unrecognized time: " + c;
      c = d[1] + "-" + d[2] + "-" + d[3] + " " + d[4];
      d[5] &&
        ((c += ":" + d[5]),
        d[6] && ((c += ":" + d[6]), d[7] && (c += "." + d[7])));
      d[8] &&
        ((c += " UTC"),
        "Z" != d[8] && ((c += d[8]), d[9] && (c += ":" + d[9])));
      return c;
    };
    b.prototype.parseInteger = function (a, b) {
      var c = b - a;
      if (4 < c) {
        var c = c << 3,
          d = this.get(a);
        if (0 === d) c -= 8;
        else for (; 128 > d; ) (d <<= 1), --c;
        return "(" + c + " bit)";
      }
      c = 0;
      for (d = a; d < b; ++d) c = (c << 8) | this.get(d);
      return c;
    };
    b.prototype.parseBitString = function (a, b) {
      var c = this.get(a),
        d = ((b - a - 1) << 3) - c,
        e = "(" + d + " bit)";
      if (20 >= d)
        for (var f = c, e = e + " ", c = b - 1; c > a; --c) {
          for (d = this.get(c); 8 > f; ++f) e += (d >> f) & 1 ? "1" : "0";
          f = 0;
        }
      return e;
    };
    b.prototype.parseOctetString = function (a, b) {
      var c = b - a,
        d = "(" + c + " byte) ";
      100 < c && (b = a + 100);
      for (var e = a; e < b; ++e) d += this.hexByte(this.get(e));
      100 < c && (d += "â€¦");
      return d;
    };
    b.prototype.parseOID = function (a, b) {
      for (var c = "", d = 0, e = 0, f = a; f < b; ++f) {
        var g = this.get(f),
          d = (d << 7) | (g & 127),
          e = e + 7;
        g & 128 ||
          ("" === c
            ? ((c = 80 > d ? (40 > d ? 0 : 1) : 2),
              (c = c + "." + (d - 40 * c)))
            : (c += "." + (31 <= e ? "bigint" : d)),
          (d = e = 0));
      }
      return c;
    };
    c.prototype.typeName = function () {
      if (this.tag === a) return "unknown";
      var b = this.tag & 31;
      switch (this.tag >> 6) {
        case 0:
          switch (b) {
            case 0:
              return "EOC";
            case 1:
              return "BOOLEAN";
            case 2:
              return "INTEGER";
            case 3:
              return "BIT_STRING";
            case 4:
              return "OCTET_STRING";
            case 5:
              return "NULL";
            case 6:
              return "OBJECT_IDENTIFIER";
            case 7:
              return "ObjectDescriptor";
            case 8:
              return "EXTERNAL";
            case 9:
              return "REAL";
            case 10:
              return "ENUMERATED";
            case 11:
              return "EMBEDDED_PDV";
            case 12:
              return "UTF8String";
            case 16:
              return "SEQUENCE";
            case 17:
              return "SET";
            case 18:
              return "NumericString";
            case 19:
              return "PrintableString";
            case 20:
              return "TeletexString";
            case 21:
              return "VideotexString";
            case 22:
              return "IA5String";
            case 23:
              return "UTCTime";
            case 24:
              return "GeneralizedTime";
            case 25:
              return "GraphicString";
            case 26:
              return "VisibleString";
            case 27:
              return "GeneralString";
            case 28:
              return "UniversalString";
            case 30:
              return "BMPString";
            default:
              return "Universal_" + b.toString(16);
          }
        case 1:
          return "Application_" + b.toString(16);
        case 2:
          return "[" + b + "]";
        case 3:
          return "Private_" + b.toString(16);
      }
    };
    c.prototype.reSeemsASCII = /^[ -~]+$/;
    c.prototype.content = function () {
      if (this.tag === a) return null;
      var b = this.tag >> 6,
        c = this.tag & 31,
        d = this.posContent(),
        e = Math.abs(this.length);
      if (0 !== b) {
        if (null !== this.sub) return "(" + this.sub.length + " elem)";
        b = this.stream.parseStringISO(d, d + Math.min(e, 100));
        return this.reSeemsASCII.test(b)
          ? b.substring(0, 200) + (200 < b.length ? "â€¦" : "")
          : this.stream.parseOctetString(d, d + e);
      }
      switch (c) {
        case 1:
          return 0 === this.stream.get(d) ? "false" : "true";
        case 2:
          return this.stream.parseInteger(d, d + e);
        case 3:
          return this.sub
            ? "(" + this.sub.length + " elem)"
            : this.stream.parseBitString(d, d + e);
        case 4:
          return this.sub
            ? "(" + this.sub.length + " elem)"
            : this.stream.parseOctetString(d, d + e);
        case 6:
          return this.stream.parseOID(d, d + e);
        case 16:
        case 17:
          return "(" + this.sub.length + " elem)";
        case 12:
          return this.stream.parseStringUTF(d, d + e);
        case 18:
        case 19:
        case 20:
        case 21:
        case 22:
        case 26:
          return this.stream.parseStringISO(d, d + e);
        case 30:
          return this.stream.parseStringBMP(d, d + e);
        case 23:
        case 24:
          return this.stream.parseTime(d, d + e);
      }
      return null;
    };
    c.prototype.toString = function () {
      return (
        this.typeName() +
        "@" +
        this.stream.pos +
        "[header:" +
        this.header +
        ",length:" +
        this.length +
        ",sub:" +
        (null === this.sub ? "null" : this.sub.length) +
        "]"
      );
    };
    c.prototype.print = function (b) {
      b === a && (b = "");
      document.writeln(b + this);
      if (null !== this.sub) {
        b += "  ";
        for (var c = 0, d = this.sub.length; c < d; ++c) this.sub[c].print(b);
      }
    };
    c.prototype.toPrettyString = function (b) {
      b === a && (b = "");
      var c = b + this.typeName() + " @" + this.stream.pos;
      0 <= this.length && (c += "+");
      c += this.length;
      this.tag & 32
        ? (c += " (constructed)")
        : (3 != this.tag && 4 != this.tag) ||
          null === this.sub ||
          (c += " (encapsulates)");
      c += "\n";
      if (null !== this.sub) {
        b += "  ";
        for (var d = 0, e = this.sub.length; d < e; ++d)
          c += this.sub[d].toPrettyString(b);
      }
      return c;
    };
    c.prototype.toDOM = function () {
      var a = d.tag("div", "node");
      a.asn1 = this;
      var b = d.tag("div", "head"),
        c = this.typeName().replace(/_/g, " ");
      b.innerHTML = c;
      var e = this.content();
      null !== e &&
        ((e = String(e).replace(/</g, "&lt;")),
        (c = d.tag("span", "preview")),
        c.appendChild(d.text(e)),
        b.appendChild(c));
      a.appendChild(b);
      this.node = a;
      this.head = b;
      var f = d.tag("div", "value"),
        c = "Offset: " + this.stream.pos + "<br/>",
        c = c + ("Length: " + this.header + "+"),
        c =
          0 <= this.length
            ? c + this.length
            : c + (-this.length + " (undefined)");
      this.tag & 32
        ? (c += "<br/>(constructed)")
        : (3 != this.tag && 4 != this.tag) ||
          null === this.sub ||
          (c += "<br/>(encapsulates)");
      null !== e &&
        ((c += "<br/>Value:<br/><b>" + e + "</b>"),
        "object" === typeof oids && 6 == this.tag && (e = oids[e])) &&
        (e.d && (c += "<br/>" + e.d),
        e.c && (c += "<br/>" + e.c),
        e.w && (c += "<br/>(warning!)"));
      f.innerHTML = c;
      a.appendChild(f);
      c = d.tag("div", "sub");
      if (null !== this.sub)
        for (e = 0, f = this.sub.length; e < f; ++e)
          c.appendChild(this.sub[e].toDOM());
      a.appendChild(c);
      b.onclick = function () {
        a.className =
          "node collapsed" == a.className ? "node" : "node collapsed";
      };
      return a;
    };
    c.prototype.posStart = function () {
      return this.stream.pos;
    };
    c.prototype.posContent = function () {
      return this.stream.pos + this.header;
    };
    c.prototype.posEnd = function () {
      return this.stream.pos + this.header + Math.abs(this.length);
    };
    c.prototype.fakeHover = function (a) {
      this.node.className += " hover";
      a && (this.head.className += " hover");
    };
    c.prototype.fakeOut = function (a) {
      var b = / ?hover/;
      this.node.className = this.node.className.replace(b, "");
      a && (this.head.className = this.head.className.replace(b, ""));
    };
    c.prototype.toHexDOM_sub = function (a, b, c, e, f) {
      e >= f ||
        ((b = d.tag("span", b)),
        b.appendChild(d.text(c.hexDump(e, f))),
        a.appendChild(b));
    };
    c.prototype.toHexDOM = function (b) {
      var c = d.tag("span", "hex");
      b === a && (b = c);
      this.head.hexNode = c;
      this.head.onmouseover = function () {
        this.hexNode.className = "hexCurrent";
      };
      this.head.onmouseout = function () {
        this.hexNode.className = "hex";
      };
      c.asn1 = this;
      c.onmouseover = function () {
        var a = !b.selected;
        a && ((b.selected = this.asn1), (this.className = "hexCurrent"));
        this.asn1.fakeHover(a);
      };
      c.onmouseout = function () {
        var a = b.selected == this.asn1;
        this.asn1.fakeOut(a);
        a && ((b.selected = null), (this.className = "hex"));
      };
      this.toHexDOM_sub(
        c,
        "tag",
        this.stream,
        this.posStart(),
        this.posStart() + 1
      );
      this.toHexDOM_sub(
        c,
        0 <= this.length ? "dlen" : "ulen",
        this.stream,
        this.posStart() + 1,
        this.posContent()
      );
      if (null === this.sub)
        c.appendChild(
          d.text(this.stream.hexDump(this.posContent(), this.posEnd()))
        );
      else if (0 < this.sub.length) {
        var e = this.sub[0],
          f = this.sub[this.sub.length - 1];
        this.toHexDOM_sub(
          c,
          "intro",
          this.stream,
          this.posContent(),
          e.posStart()
        );
        for (var e = 0, g = this.sub.length; e < g; ++e)
          c.appendChild(this.sub[e].toHexDOM(b));
        this.toHexDOM_sub(c, "outro", this.stream, f.posEnd(), this.posEnd());
      }
      return c;
    };
    c.prototype.toHexString = function (a) {
      return this.stream.hexDump(this.posStart(), this.posEnd(), !0);
    };
    c.decodeLength = function (a) {
      var b = a.get(),
        c = b & 127;
      if (c == b) return c;
      if (3 < c)
        throw "Length over 24 bits not supported at position " + (a.pos - 1);
      if (0 === c) return -1;
      for (var d = (b = 0); d < c; ++d) b = (b << 8) | a.get();
      return b;
    };
    c.hasContent = function (a, d, f) {
      if (a & 32) return !0;
      if (3 > a || 4 < a) return !1;
      var h = new b(f);
      3 == a && h.get();
      if ((h.get() >> 6) & 1) return !1;
      try {
        var k = c.decodeLength(h);
        return h.pos - f.pos + k == d;
      } catch (m) {
        return !1;
      }
    };
    c.decode = function (a) {
      a instanceof b || (a = new b(a, 0));
      var d = new b(a),
        f = a.get(),
        h = c.decodeLength(a),
        k = a.pos - d.pos,
        m = null;
      if (c.hasContent(f, h, a)) {
        var n = a.pos;
        3 == f && a.get();
        m = [];
        if (0 <= h) {
          for (var r = n + h; a.pos < r; ) m[m.length] = c.decode(a);
          if (a.pos != r)
            throw (
              "Content size is not correct for container starting at offset " +
              n
            );
        } else
          try {
            for (;;) {
              r = c.decode(a);
              if (0 === r.tag) break;
              m[m.length] = r;
            }
            h = n - a.pos;
          } catch (p) {
            throw "Exception while decoding undefined length content: " + p;
          }
      } else a.pos += h;
      return new c(d, k, h, f, m);
    };
    c.test = function () {
      for (
        var a = [
            { value: [39], expected: 39 },
            { value: [129, 201], expected: 201 },
            { value: [131, 254, 220, 186], expected: 16702650 },
          ],
          d = 0,
          f = a.length;
        d < f;
        ++d
      ) {
        var h = new b(a[d].value, 0),
          h = c.decodeLength(h);
        h != a[d].expected &&
          document.write(
            "In test[" + d + "] expected " + a[d].expected + " got " + h + "\n"
          );
      }
    };
    window.ASN1 = c;
  })();
  ASN1.prototype.getHexStringValue = function () {
    return this.toHexString().substr(2 * this.header, 2 * this.length);
  };
  H.prototype.parseKey = function (a) {
    try {
      var b = 0,
        c = 0,
        d = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/.test(a)
          ? Hex.decode(a)
          : Base64.unarmor(a),
        f = ASN1.decode(d);
      3 === f.sub.length && (f = f.sub[2].sub[0]);
      if (9 === f.sub.length) {
        b = f.sub[1].getHexStringValue();
        this.n = E(b, 16);
        c = f.sub[2].getHexStringValue();
        this.e = parseInt(c, 16);
        var h = f.sub[3].getHexStringValue();
        this.d = E(h, 16);
        var k = f.sub[4].getHexStringValue();
        this.p = E(k, 16);
        var m = f.sub[5].getHexStringValue();
        this.q = E(m, 16);
        var r = f.sub[6].getHexStringValue();
        this.dmp1 = E(r, 16);
        var n = f.sub[7].getHexStringValue();
        this.dmq1 = E(n, 16);
        var p = f.sub[8].getHexStringValue();
        this.coeff = E(p, 16);
      } else if (2 === f.sub.length) {
        var t = f.sub[1].sub[0],
          b = t.sub[0].getHexStringValue();
        this.n = E(b, 16);
        c = t.sub[1].getHexStringValue();
        this.e = parseInt(c, 16);
      } else return !1;
      return !0;
    } catch (u) {
      return !1;
    }
  };
  H.prototype.getPrivateBaseKey = function () {
    var a = {
      array: [
        new KJUR.asn1.DERInteger({ int: 0 }),
        new KJUR.asn1.DERInteger({ bigint: this.n }),
        new KJUR.asn1.DERInteger({ int: this.e }),
        new KJUR.asn1.DERInteger({ bigint: this.d }),
        new KJUR.asn1.DERInteger({ bigint: this.p }),
        new KJUR.asn1.DERInteger({ bigint: this.q }),
        new KJUR.asn1.DERInteger({ bigint: this.dmp1 }),
        new KJUR.asn1.DERInteger({ bigint: this.dmq1 }),
        new KJUR.asn1.DERInteger({ bigint: this.coeff }),
      ],
    };
    return new KJUR.asn1.DERSequence(a).getEncodedHex();
  };
  H.prototype.getPrivateBaseKeyB64 = function () {
    return V(this.getPrivateBaseKey());
  };
  H.prototype.getPublicBaseKey = function () {
    var a = {
        array: [
          new KJUR.asn1.DERObjectIdentifier({ oid: "1.2.840.113549.1.1.1" }),
          new KJUR.asn1.DERNull(),
        ],
      },
      b = new KJUR.asn1.DERSequence(a),
      a = {
        array: [
          new KJUR.asn1.DERInteger({ bigint: this.n }),
          new KJUR.asn1.DERInteger({ int: this.e }),
        ],
      },
      a = { hex: "00" + new KJUR.asn1.DERSequence(a).getEncodedHex() },
      a = new KJUR.asn1.DERBitString(a),
      a = { array: [b, a] };
    return new KJUR.asn1.DERSequence(a).getEncodedHex();
  };
  H.prototype.getPublicBaseKeyB64 = function () {
    return V(this.getPublicBaseKey());
  };
  H.prototype.wordwrap = function (a, b) {
    b = b || 64;
    return a
      ? a
          .match(RegExp("(.{1," + b + "})( +|$\n?)|(.{1," + b + "})", "g"))
          .join("\n")
      : a;
  };
  H.prototype.getPrivateKey = function () {
    return (
      "-----BEGIN RSA PRIVATE KEY-----\n" +
      (this.wordwrap(this.getPrivateBaseKeyB64()) + "\n") +
      "-----END RSA PRIVATE KEY-----"
    );
  };
  H.prototype.getPublicKey = function () {
    return (
      "-----BEGIN PUBLIC KEY-----\n" +
      (this.wordwrap(this.getPublicBaseKeyB64()) + "\n") +
      "-----END PUBLIC KEY-----"
    );
  };
  H.prototype.hasPublicKeyProperty = function (a) {
    a = a || {};
    return a.hasOwnProperty("n") && a.hasOwnProperty("e");
  };
  H.prototype.hasPrivateKeyProperty = function (a) {
    a = a || {};
    return (
      a.hasOwnProperty("n") &&
      a.hasOwnProperty("e") &&
      a.hasOwnProperty("d") &&
      a.hasOwnProperty("p") &&
      a.hasOwnProperty("q") &&
      a.hasOwnProperty("dmp1") &&
      a.hasOwnProperty("dmq1") &&
      a.hasOwnProperty("coeff")
    );
  };
  H.prototype.parsePropertiesFrom = function (a) {
    this.n = a.n;
    this.e = a.e;
    a.hasOwnProperty("d") &&
      ((this.d = a.d),
      (this.p = a.p),
      (this.q = a.q),
      (this.dmp1 = a.dmp1),
      (this.dmq1 = a.dmq1),
      (this.coeff = a.coeff));
  };
  var T = function (a) {
    H.call(this);
    a &&
      ("string" === typeof a
        ? this.parseKey(a)
        : (this.hasPrivateKeyProperty(a) || this.hasPublicKeyProperty(a)) &&
          this.parsePropertiesFrom(a));
  };
  T.prototype = new H();
  T.prototype.constructor = T;
  k = function (a) {
    a = a || {};
    this.default_key_size = parseInt(a.default_key_size) || 1024;
    this.default_public_exponent = a.default_public_exponent || "010001";
    this.log = a.log || !1;
    this.key = null;
  };
  k.prototype.setKey = function (a) {
    this.log &&
      this.key &&
      console.warn("A key was already set, overriding existing.");
    this.key = new T(a);
  };
  k.prototype.setPrivateKey = function (a) {
    this.setKey(a);
  };
  k.prototype.setPublicKey = function (a) {
    this.setKey(a);
  };
  k.prototype.decrypt = function (a) {
    try {
      return this.getKey().decrypt(J(a));
    } catch (b) {
      return !1;
    }
  };
  k.prototype.encrypt = function (a) {
    try {
      return V(this.getKey().encrypt(a));
    } catch (b) {
      return !1;
    }
  };
  k.prototype.getKey = function (a) {
    if (!this.key) {
      this.key = new T();
      if (a && "[object Function]" === {}.toString.call(a)) {
        this.key.generateAsync(
          this.default_key_size,
          this.default_public_exponent,
          a
        );
        return;
      }
      this.key.generate(this.default_key_size, this.default_public_exponent);
    }
    return this.key;
  };
  k.prototype.getPrivateKey = function () {
    return this.getKey().getPrivateKey();
  };
  k.prototype.getPrivateKeyB64 = function () {
    return this.getKey().getPrivateBaseKeyB64();
  };
  k.prototype.getPublicKey = function () {
    return this.getKey().getPublicKey();
  };
  k.prototype.getPublicKeyB64 = function () {
    return this.getKey().getPublicBaseKeyB64();
  };``
  k.version = "2.3.1";
  L.JSEncrypt = k;
});
var com_sbps_system_tds2 = com_sbps_system_tds2 || {};
com_sbps_system_tds2.CryptoJS = com_sbps_system.CryptoJS;
com_sbps_system_tds2.JSEncrypt = com_sbps_system.JSEncrypt;
(function (L) {
  var b = L.CryptoJS,
    h = L.JSEncrypt;
  L.local = {
    token_url: "https://stbtoken.sps-system.com/token/generateTds2Token",
    pubkey:
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BMW0T80ZB48dIIEkhcucncJTIthJtKnZN1vh3vfTCbuu7e1OXERSolFa8Me9bTnHqR3y8fXGXXYIxU8BBHBYWbNZWk9wMAn+Hcej8091zYu5BqAlzRxs1S9k6bX/aH24l7qXxzfW6rX71qYuP3v9RRwgnd3tOcWN9wrsIhryTryoC6KSVeh1z/27k1W8uVKCXJniihZ99nUtRSSoST9nZdXDLXyehTBZyZKAWEH5I5wRc3VnjkMUBo5Ksi7G8x0pqLrCgk46Z0YHMpU4M8TORYA1ZyFug7gCOOumfzWiJRBJmctvmwrnfobGC7z/6zSiZH/3YbigZgTsw2073cp0wIDAQAB",
    createUuid: function () {
      var b = "",
        h,
        m;
      for (h = 0; 32 > h; h++) {
        m = (16 * Math.random()) | 0;
        if (8 == h || 12 == h || 16 == h || 20 == h) b += "-";
        b += (12 == h ? 4 : 16 == h ? (m & 3) | 8 : m).toString(16);
      }
      return b;
    },
    encrypt: function (c) {
      var r = c.merchantId,
        m = c.serviceId,
        y =
          (void 0 === c.billingLastName || null === c.billingLastName
            ? ""
            : c.billingLastName) +
          "\t" +
          (void 0 === c.billingFirstName || null === c.billingFirstName
            ? ""
            : c.billingFirstName) +
          "\t" +
          (void 0 === c.billingPostalCode || null === c.billingPostalCode
            ? ""
            : c.billingPostalCode) +
          "\t" +
          (void 0 === c.billingCity || null === c.billingCity
            ? ""
            : c.billingCity) +
          "\t" +
          (void 0 === c.billingAddress1 || null === c.billingAddress1
            ? ""
            : c.billingAddress1) +
          "\t" +
          (void 0 === c.billingAddress2 || null === c.billingAddress2
            ? ""
            : c.billingAddress2) +
          "\t" +
          (void 0 === c.billingAddress3 || null === c.billingAddress3
            ? ""
            : c.billingAddress3) +
          "\t" +
          (void 0 === c.billingPhone || null === c.billingPhone
            ? ""
            : c.billingPhone) +
          "\t" +
          (void 0 === c.workPhone || null === c.workPhone ? "" : c.workPhone) +
          "\t" +
          (void 0 === c.shippingPostalCode || null === c.shippingPostalCode
            ? ""
            : c.shippingPostalCode) +
          "\t" +
          (void 0 === c.shippingCity || null === c.shippingCity
            ? ""
            : c.shippingCity) +
          "\t" +
          (void 0 === c.shippingAddress1 || null === c.shippingAddress1
            ? ""
            : c.shippingAddress1) +
          "\t" +
          (void 0 === c.shippingAddress2 || null === c.shippingAddress2
            ? ""
            : c.shippingAddress2) +
          "\t" +
          (void 0 === c.shippingAddress3 || null === c.shippingAddress3
            ? ""
            : c.shippingAddress3) +
          "\t" +
          (void 0 === c.email || null === c.email ? "" : c.email);
      c = b.lib.WordArray.random(16);
      m = b.PBKDF2(r + m, c, { keySize: 8 });
      r = b.lib.WordArray.random(16);
      y = b.AES.encrypt(y, m, {
        iv: r,
        mode: b.mode.CBC,
        padding: b.pad.Pkcs7,
      });
      y = b.enc.Base64.stringify(y.ciphertext);
      c = b.enc.Base64.stringify(c) + ":" + b.enc.Base64.stringify(r);
      r = new h();
      r.setPublicKey(this.pubkey);
      return { key: r.encrypt(c), value: y };
    },
    createUrl: function (b, h) {
      var m = new Date(),
        m =
          m.getFullYear() +
          "" +
          m.getMonth() +
          1 +
          "" +
          m.getDate() +
          "" +
          m.getHours() +
          "" +
          m.getMinutes() +
          "" +
          m.getSeconds(),
        y = this.encrypt(h);
      return (
        this.token_url +
        "?callback=com_sbps_system_tds2.rm['" +
        b +
        "'].cb&mId=" +
        h.merchantId +
        "&sId=" +
        h.serviceId +
        "&key=" +
        encodeURIComponent(y.key) +
        "&val=" +
        encodeURIComponent(y.value) +
        "&requestTime=" +
        m
      );
    },
    createRequest: function (b, h) {
      return {
        cb: function (b) {
          h(b.tokenRes);
        },
        run: function () {
          var h = document.createElement("script");
          h.charset = "UTF-8";
          h.src = b;
          document.body.appendChild(h);
        },
      };
    },
  };
  L.rm = {};
  L.generateToken = function (b, h) {
    var m = this.local.createUuid(),
      y = this.local.createUrl(m, b),
      y = this.local.createRequest(y, h);
    this.rm[m] = y;
    y.run();
  };
})(com_sbps_system_tds2);
