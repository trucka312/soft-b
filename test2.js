/*
 CryptoJS v3.1.2
 code.google.com/p/crypto-js
 (c) 2009-2013 by Jeff Mott. All rights reserved.
 code.google.com/p/crypto-js/wiki/License
*/
var com_sbps_system = com_sbps_system || {};
(function (M) {
  var b = M.CryptoJS,
    b =
      b ||
      (function (b, p) {
        var m = {},
          c = (m.lib = {}),
          y = function () {},
          A = (c.Base = {
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
          B = (c.WordArray = A.extend({
            init: function (d, b) {
              d = this.words = d || [];
              this.sigBytes = b != p ? b : 4 * d.length;
            },
            toString: function (d) {
              return (d || D).stringify(this);
            },
            concat: function (d) {
              var b = this.words,
                r = d.words,
                q = this.sigBytes;
              d = d.sigBytes;
              this.clamp();
              if (q % 4)
                for (var z = 0; z < d; z++)
                  b[(q + z) >>> 2] |=
                    ((r[z >>> 2] >>> (24 - (z % 4) * 8)) & 255) <<
                    (24 - ((q + z) % 4) * 8);
              else if (65535 < r.length)
                for (z = 0; z < d; z += 4) b[(q + z) >>> 2] = r[z >>> 2];
              else b.push.apply(b, r);
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
              for (var n = [], r = 0; r < d; r += 4)
                n.push((4294967296 * b.random()) | 0);
              return new B.init(n, d);
            },
          })),
          C = (m.enc = {}),
          D = (C.Hex = {
            stringify: function (d) {
              var b = d.words;
              d = d.sigBytes;
              for (var r = [], q = 0; q < d; q++) {
                var z = (b[q >>> 2] >>> (24 - (q % 4) * 8)) & 255;
                r.push((z >>> 4).toString(16));
                r.push((z & 15).toString(16));
              }
              return r.join("");
            },
            parse: function (d) {
              for (var b = d.length, r = [], q = 0; q < b; q += 2)
                r[q >>> 3] |=
                  parseInt(d.substr(q, 2), 16) << (24 - (q % 8) * 4);
              return new B.init(r, b / 2);
            },
          }),
          g = (C.Latin1 = {
            stringify: function (d) {
              var b = d.words;
              d = d.sigBytes;
              for (var r = [], q = 0; q < d; q++)
                r.push(
                  String.fromCharCode((b[q >>> 2] >>> (24 - (q % 4) * 8)) & 255)
                );
              return r.join("");
            },
            parse: function (d) {
              for (var b = d.length, r = [], q = 0; q < b; q++)
                r[q >>> 2] |= (d.charCodeAt(q) & 255) << (24 - (q % 4) * 8);
              return new B.init(r, b);
            },
          }),
          G = (C.Utf8 = {
            stringify: function (d) {
              try {
                return decodeURIComponent(escape(g.stringify(d)));
              } catch (b) {
                throw Error("Malformed UTF-8 data");
              }
            },
            parse: function (d) {
              return g.parse(unescape(encodeURIComponent(d)));
            },
          }),
          H = (c.BufferedBlockAlgorithm = A.extend({
            reset: function () {
              this._data = new B.init();
              this._nDataBytes = 0;
            },
            _append: function (d) {
              "string" == typeof d && (d = G.parse(d));
              this._data.concat(d);
              this._nDataBytes += d.sigBytes;
            },
            _process: function (d) {
              var n = this._data,
                r = n.words,
                q = n.sigBytes,
                z = this.blockSize,
                g = q / (4 * z),
                g = d ? b.ceil(g) : b.max((g | 0) - this._minBufferSize, 0);
              d = g * z;
              q = b.min(4 * d, q);
              if (d) {
                for (var c = 0; c < d; c += z) this._doProcessBlock(r, c);
                c = r.splice(0, d);
                n.sigBytes -= q;
              }
              return new B.init(c, q);
            },
            clone: function () {
              var d = A.clone.call(this);
              d._data = this._data.clone();
              return d;
            },
            _minBufferSize: 0,
          }));
        c.Hasher = H.extend({
          cfg: A.extend(),
          init: function (d) {
            this.cfg = this.cfg.extend(d);
            this.reset();
          },
          reset: function () {
            H.reset.call(this);
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
            return function (b, r) {
              return new d.init(r).finalize(b);
            };
          },
          _createHmacHelper: function (d) {
            return function (b, r) {
              return new J.HMAC.init(d, r).finalize(b);
            };
          },
        });
        var J = (m.algo = {});
        return m;
      })(Math);
  (function () {
    var h = b,
      p = h.lib.WordArray;
    h.enc.Base64 = {
      stringify: function (b) {
        var c = b.words,
          p = b.sigBytes,
          h = this._map;
        b.clamp();
        b = [];
        for (var B = 0; B < p; B += 3)
          for (
            var C =
                (((c[B >>> 2] >>> (24 - (B % 4) * 8)) & 255) << 16) |
                (((c[(B + 1) >>> 2] >>> (24 - ((B + 1) % 4) * 8)) & 255) << 8) |
                ((c[(B + 2) >>> 2] >>> (24 - ((B + 2) % 4) * 8)) & 255),
              D = 0;
            4 > D && B + 0.75 * D < p;
            D++
          )
            b.push(h.charAt((C >>> (6 * (3 - D))) & 63));
        if ((c = h.charAt(64))) for (; b.length % 4; ) b.push(c);
        return b.join("");
      },
      parse: function (b) {
        var c = b.length,
          h = this._map,
          A = h.charAt(64);
        A && ((A = b.indexOf(A)), -1 != A && (c = A));
        for (var A = [], B = 0, C = 0; C < c; C++)
          if (C % 4) {
            var D = h.indexOf(b.charAt(C - 1)) << ((C % 4) * 2),
              g = h.indexOf(b.charAt(C)) >>> (6 - (C % 4) * 2);
            A[B >>> 2] |= (D | g) << (24 - (B % 4) * 8);
            B++;
          }
        return p.create(A, B);
      },
      _map: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
    };
  })();
  (function (h) {
    function p(b, c, d, n, r, q, z) {
      b = b + ((c & d) | (~c & n)) + r + z;
      return ((b << q) | (b >>> (32 - q))) + c;
    }
    function m(b, c, d, n, r, q, z) {
      b = b + ((c & n) | (d & ~n)) + r + z;
      return ((b << q) | (b >>> (32 - q))) + c;
    }
    function c(b, c, d, n, r, q, z) {
      b = b + (c ^ d ^ n) + r + z;
      return ((b << q) | (b >>> (32 - q))) + c;
    }
    function y(b, c, d, n, r, q, z) {
      b = b + (d ^ (c | ~n)) + r + z;
      return ((b << q) | (b >>> (32 - q))) + c;
    }
    for (
      var A = b,
        B = A.lib,
        C = B.WordArray,
        D = B.Hasher,
        B = A.algo,
        g = [],
        G = 0;
      64 > G;
      G++
    )
      g[G] = (4294967296 * h.abs(h.sin(G + 1))) | 0;
    B = B.MD5 = D.extend({
      _doReset: function () {
        this._hash = new C.init([
          1732584193, 4023233417, 2562383102, 271733878,
        ]);
      },
      _doProcessBlock: function (b, h) {
        for (var d = 0; 16 > d; d++) {
          var n = h + d,
            r = b[n];
          b[n] =
            (((r << 8) | (r >>> 24)) & 16711935) |
            (((r << 24) | (r >>> 8)) & 4278255360);
        }
        var d = this._hash.words,
          n = b[h + 0],
          r = b[h + 1],
          q = b[h + 2],
          z = b[h + 3],
          F = b[h + 4],
          B = b[h + 5],
          C = b[h + 6],
          A = b[h + 7],
          D = b[h + 8],
          G = b[h + 9],
          L = b[h + 10],
          O = b[h + 11],
          S = b[h + 12],
          R = b[h + 13],
          Q = b[h + 14],
          P = b[h + 15],
          w = d[0],
          l = d[1],
          x = d[2],
          t = d[3],
          w = p(w, l, x, t, n, 7, g[0]),
          t = p(t, w, l, x, r, 12, g[1]),
          x = p(x, t, w, l, q, 17, g[2]),
          l = p(l, x, t, w, z, 22, g[3]),
          w = p(w, l, x, t, F, 7, g[4]),
          t = p(t, w, l, x, B, 12, g[5]),
          x = p(x, t, w, l, C, 17, g[6]),
          l = p(l, x, t, w, A, 22, g[7]),
          w = p(w, l, x, t, D, 7, g[8]),
          t = p(t, w, l, x, G, 12, g[9]),
          x = p(x, t, w, l, L, 17, g[10]),
          l = p(l, x, t, w, O, 22, g[11]),
          w = p(w, l, x, t, S, 7, g[12]),
          t = p(t, w, l, x, R, 12, g[13]),
          x = p(x, t, w, l, Q, 17, g[14]),
          l = p(l, x, t, w, P, 22, g[15]),
          w = m(w, l, x, t, r, 5, g[16]),
          t = m(t, w, l, x, C, 9, g[17]),
          x = m(x, t, w, l, O, 14, g[18]),
          l = m(l, x, t, w, n, 20, g[19]),
          w = m(w, l, x, t, B, 5, g[20]),
          t = m(t, w, l, x, L, 9, g[21]),
          x = m(x, t, w, l, P, 14, g[22]),
          l = m(l, x, t, w, F, 20, g[23]),
          w = m(w, l, x, t, G, 5, g[24]),
          t = m(t, w, l, x, Q, 9, g[25]),
          x = m(x, t, w, l, z, 14, g[26]),
          l = m(l, x, t, w, D, 20, g[27]),
          w = m(w, l, x, t, R, 5, g[28]),
          t = m(t, w, l, x, q, 9, g[29]),
          x = m(x, t, w, l, A, 14, g[30]),
          l = m(l, x, t, w, S, 20, g[31]),
          w = c(w, l, x, t, B, 4, g[32]),
          t = c(t, w, l, x, D, 11, g[33]),
          x = c(x, t, w, l, O, 16, g[34]),
          l = c(l, x, t, w, Q, 23, g[35]),
          w = c(w, l, x, t, r, 4, g[36]),
          t = c(t, w, l, x, F, 11, g[37]),
          x = c(x, t, w, l, A, 16, g[38]),
          l = c(l, x, t, w, L, 23, g[39]),
          w = c(w, l, x, t, R, 4, g[40]),
          t = c(t, w, l, x, n, 11, g[41]),
          x = c(x, t, w, l, z, 16, g[42]),
          l = c(l, x, t, w, C, 23, g[43]),
          w = c(w, l, x, t, G, 4, g[44]),
          t = c(t, w, l, x, S, 11, g[45]),
          x = c(x, t, w, l, P, 16, g[46]),
          l = c(l, x, t, w, q, 23, g[47]),
          w = y(w, l, x, t, n, 6, g[48]),
          t = y(t, w, l, x, A, 10, g[49]),
          x = y(x, t, w, l, Q, 15, g[50]),
          l = y(l, x, t, w, B, 21, g[51]),
          w = y(w, l, x, t, S, 6, g[52]),
          t = y(t, w, l, x, z, 10, g[53]),
          x = y(x, t, w, l, L, 15, g[54]),
          l = y(l, x, t, w, r, 21, g[55]),
          w = y(w, l, x, t, D, 6, g[56]),
          t = y(t, w, l, x, P, 10, g[57]),
          x = y(x, t, w, l, C, 15, g[58]),
          l = y(l, x, t, w, R, 21, g[59]),
          w = y(w, l, x, t, F, 6, g[60]),
          t = y(t, w, l, x, O, 10, g[61]),
          x = y(x, t, w, l, q, 15, g[62]),
          l = y(l, x, t, w, G, 21, g[63]);
        d[0] = (d[0] + w) | 0;
        d[1] = (d[1] + l) | 0;
        d[2] = (d[2] + x) | 0;
        d[3] = (d[3] + t) | 0;
      },
      _doFinalize: function () {
        var b = this._data,
          c = b.words,
          d = 8 * this._nDataBytes,
          n = 8 * b.sigBytes;
        c[n >>> 5] |= 128 << (24 - (n % 32));
        var r = h.floor(d / 4294967296);
        c[(((n + 64) >>> 9) << 4) + 15] =
          (((r << 8) | (r >>> 24)) & 16711935) |
          (((r << 24) | (r >>> 8)) & 4278255360);
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
    A.MD5 = D._createHelper(B);
    A.HmacMD5 = D._createHmacHelper(B);
  })(Math);
  (function () {
    var h = b,
      p = h.lib,
      m = p.Base,
      c = p.WordArray,
      p = h.algo,
      y = (p.EvpKDF = m.extend({
        cfg: m.extend({ keySize: 4, hasher: p.MD5, iterations: 1 }),
        init: function (b) {
          this.cfg = this.cfg.extend(b);
        },
        compute: function (b, h) {
          for (
            var m = this.cfg,
              p = m.hasher.create(),
              g = c.create(),
              y = g.words,
              H = m.keySize,
              m = m.iterations;
            y.length < H;

          ) {
            J && p.update(J);
            var J = p.update(b).finalize(h);
            p.reset();
            for (var d = 1; d < m; d++) (J = p.finalize(J)), p.reset();
            g.concat(J);
          }
          g.sigBytes = 4 * H;
          return g;
        },
      }));
    h.EvpKDF = function (b, c, h) {
      return y.create(h).compute(b, c);
    };
  })();
  b.lib.Cipher ||
    (function (h) {
      var p = b,
        m = p.lib,
        c = m.Base,
        y = m.WordArray,
        A = m.BufferedBlockAlgorithm,
        B = p.enc.Base64,
        C = p.algo.EvpKDF,
        D = (m.Cipher = A.extend({
          cfg: c.extend(),
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
              encrypt: function (q, c, g) {
                return ("string" == typeof c ? n : d).encrypt(b, q, c, g);
              },
              decrypt: function (q, c, g) {
                return ("string" == typeof c ? n : d).decrypt(b, q, c, g);
              },
            };
          },
        }));
      m.StreamCipher = D.extend({
        _doFinalize: function () {
          return this._process(!0);
        },
        blockSize: 1,
      });
      var g = (p.mode = {}),
        G = function (b, d, c) {
          var n = this._iv;
          n ? (this._iv = h) : (n = this._prevBlock);
          for (var g = 0; g < c; g++) b[d + g] ^= n[g];
        },
        H = (m.BlockCipherMode = c.extend({
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
      H.Encryptor = H.extend({
        processBlock: function (b, d) {
          var c = this._cipher,
            g = c.blockSize;
          G.call(this, b, d, g);
          c.encryptBlock(b, d);
          this._prevBlock = b.slice(d, d + g);
        },
      });
      H.Decryptor = H.extend({
        processBlock: function (b, d) {
          var c = this._cipher,
            g = c.blockSize,
            n = b.slice(d, d + g);
          c.decryptBlock(b, d);
          G.call(this, b, d, g);
          this._prevBlock = n;
        },
      });
      g = g.CBC = H;
      H = (p.pad = {}).Pkcs7 = {
        pad: function (b, d) {
          for (
            var c = 4 * d,
              c = c - (b.sigBytes % c),
              g = (c << 24) | (c << 16) | (c << 8) | c,
              n = [],
              h = 0;
            h < c;
            h += 4
          )
            n.push(g);
          c = y.create(n, c);
          b.concat(c);
        },
        unpad: function (b) {
          b.sigBytes -= b.words[(b.sigBytes - 1) >>> 2] & 255;
        },
      };
      m.BlockCipher = D.extend({
        cfg: D.cfg.extend({ mode: g, padding: H }),
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
      var J = (m.CipherParams = c.extend({
          init: function (b) {
            this.mixIn(b);
          },
          toString: function (b) {
            return (b || this.formatter).stringify(this);
          },
        })),
        g = ((p.format = {}).OpenSSL = {
          stringify: function (b) {
            var d = b.ciphertext;
            b = b.salt;
            return (
              b ? y.create([1398893684, 1701076831]).concat(b).concat(d) : d
            ).toString(B);
          },
          parse: function (b) {
            b = B.parse(b);
            var d = b.words;
            if (1398893684 == d[0] && 1701076831 == d[1]) {
              var c = y.create(d.slice(2, 4));
              d.splice(0, 4);
              b.sigBytes -= 16;
            }
            return J.create({ ciphertext: b, salt: c });
          },
        }),
        d = (m.SerializableCipher = c.extend({
          cfg: c.extend({ format: g }),
          encrypt: function (b, d, c, g) {
            g = this.cfg.extend(g);
            var n = b.createEncryptor(c, g);
            d = n.finalize(d);
            n = n.cfg;
            return J.create({
              ciphertext: d,
              key: c,
              iv: n.iv,
              algorithm: b,
              mode: n.mode,
              padding: n.padding,
              blockSize: b.blockSize,
              formatter: g.format,
            });
          },
          decrypt: function (b, d, c, g) {
            g = this.cfg.extend(g);
            d = this._parse(d, g.format);
            return b.createDecryptor(c, g).finalize(d.ciphertext);
          },
          _parse: function (b, d) {
            return "string" == typeof b ? d.parse(b, this) : b;
          },
        })),
        p = ((p.kdf = {}).OpenSSL = {
          execute: function (b, d, c, g) {
            g || (g = y.random(8));
            b = C.create({ keySize: d + c }).compute(b, g);
            c = y.create(b.words.slice(d), 4 * c);
            b.sigBytes = 4 * d;
            return J.create({ key: b, iv: c, salt: g });
          },
        }),
        n = (m.PasswordBasedCipher = d.extend({
          cfg: d.cfg.extend({ kdf: p }),
          encrypt: function (b, c, g, n) {
            n = this.cfg.extend(n);
            g = n.kdf.execute(g, b.keySize, b.ivSize);
            n.iv = g.iv;
            b = d.encrypt.call(this, b, c, g.key, n);
            b.mixIn(g);
            return b;
          },
          decrypt: function (b, c, g, n) {
            n = this.cfg.extend(n);
            c = this._parse(c, n.format);
            g = n.kdf.execute(g, b.keySize, b.ivSize, c.salt);
            n.iv = g.iv;
            return d.decrypt.call(this, b, c, g.key, n);
          },
        }));
    })();
  (function () {
    for (
      var h = b,
        p = h.lib.BlockCipher,
        m = h.algo,
        c = [],
        y = [],
        A = [],
        B = [],
        C = [],
        D = [],
        g = [],
        G = [],
        H = [],
        J = [],
        d = [],
        n = 0;
      256 > n;
      n++
    )
      d[n] = 128 > n ? n << 1 : (n << 1) ^ 283;
    for (var r = 0, q = 0, n = 0; 256 > n; n++) {
      var z = q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4),
        z = (z >>> 8) ^ (z & 255) ^ 99;
      c[r] = z;
      y[z] = r;
      var F = d[r],
        I = d[F],
        M = d[I],
        K = (257 * d[z]) ^ (16843008 * z);
      A[r] = (K << 24) | (K >>> 8);
      B[r] = (K << 16) | (K >>> 16);
      C[r] = (K << 8) | (K >>> 24);
      D[r] = K;
      K = (16843009 * M) ^ (65537 * I) ^ (257 * F) ^ (16843008 * r);
      g[z] = (K << 24) | (K >>> 8);
      G[z] = (K << 16) | (K >>> 16);
      H[z] = (K << 8) | (K >>> 24);
      J[z] = K;
      r ? ((r = F ^ d[d[d[M ^ F]]]), (q ^= d[d[q]])) : (r = q = 1);
    }
    var N = [0, 1, 2, 4, 8, 16, 32, 64, 128, 27, 54],
      m = (m.AES = p.extend({
        _doReset: function () {
          for (
            var b = this._key,
              d = b.words,
              n = b.sigBytes / 4,
              b = 4 * ((this._nRounds = n + 6) + 1),
              q = (this._keySchedule = []),
              h = 0;
            h < b;
            h++
          )
            if (h < n) q[h] = d[h];
            else {
              var r = q[h - 1];
              h % n
                ? 6 < n &&
                  4 == h % n &&
                  (r =
                    (c[r >>> 24] << 24) |
                    (c[(r >>> 16) & 255] << 16) |
                    (c[(r >>> 8) & 255] << 8) |
                    c[r & 255])
                : ((r = (r << 8) | (r >>> 24)),
                  (r =
                    (c[r >>> 24] << 24) |
                    (c[(r >>> 16) & 255] << 16) |
                    (c[(r >>> 8) & 255] << 8) |
                    c[r & 255]),
                  (r ^= N[(h / n) | 0] << 24));
              q[h] = q[h - n] ^ r;
            }
          d = this._invKeySchedule = [];
          for (n = 0; n < b; n++)
            (h = b - n),
              (r = n % 4 ? q[h] : q[h - 4]),
              (d[n] =
                4 > n || 4 >= h
                  ? r
                  : g[c[r >>> 24]] ^
                    G[c[(r >>> 16) & 255]] ^
                    H[c[(r >>> 8) & 255]] ^
                    J[c[r & 255]]);
        },
        encryptBlock: function (b, d) {
          this._doCryptBlock(b, d, this._keySchedule, A, B, C, D, c);
        },
        decryptBlock: function (b, d) {
          var c = b[d + 1];
          b[d + 1] = b[d + 3];
          b[d + 3] = c;
          this._doCryptBlock(b, d, this._invKeySchedule, g, G, H, J, y);
          c = b[d + 1];
          b[d + 1] = b[d + 3];
          b[d + 3] = c;
        },
        _doCryptBlock: function (b, d, c, n, g, r, h, q) {
          for (
            var l = this._nRounds,
              m = b[d] ^ c[0],
              t = b[d + 1] ^ c[1],
              p = b[d + 2] ^ c[2],
              z = b[d + 3] ^ c[3],
              a = 4,
              e = 1;
            e < l;
            e++
          )
            var f =
                n[m >>> 24] ^
                g[(t >>> 16) & 255] ^
                r[(p >>> 8) & 255] ^
                h[z & 255] ^
                c[a++],
              E =
                n[t >>> 24] ^
                g[(p >>> 16) & 255] ^
                r[(z >>> 8) & 255] ^
                h[m & 255] ^
                c[a++],
              k =
                n[p >>> 24] ^
                g[(z >>> 16) & 255] ^
                r[(m >>> 8) & 255] ^
                h[t & 255] ^
                c[a++],
              z =
                n[z >>> 24] ^
                g[(m >>> 16) & 255] ^
                r[(t >>> 8) & 255] ^
                h[p & 255] ^
                c[a++],
              m = f,
              t = E,
              p = k;
          f =
            ((q[m >>> 24] << 24) |
              (q[(t >>> 16) & 255] << 16) |
              (q[(p >>> 8) & 255] << 8) |
              q[z & 255]) ^
            c[a++];
          E =
            ((q[t >>> 24] << 24) |
              (q[(p >>> 16) & 255] << 16) |
              (q[(z >>> 8) & 255] << 8) |
              q[m & 255]) ^
            c[a++];
          k =
            ((q[p >>> 24] << 24) |
              (q[(z >>> 16) & 255] << 16) |
              (q[(m >>> 8) & 255] << 8) |
              q[t & 255]) ^
            c[a++];
          z =
            ((q[z >>> 24] << 24) |
              (q[(m >>> 16) & 255] << 16) |
              (q[(t >>> 8) & 255] << 8) |
              q[p & 255]) ^
            c[a++];
          b[d] = f;
          b[d + 1] = E;
          b[d + 2] = k;
          b[d + 3] = z;
        },
        keySize: 8,
      }));
    h.AES = p._createHelper(m);
  })();
  M.CryptoJS = b;
})(com_sbps_system);
com_sbps_system = com_sbps_system || {};
(function (M) {
  var b = M.CryptoJS,
    b =
      b ||
      (function (b, p) {
        var m = {},
          c = (m.lib = {}),
          y = function () {},
          A = (c.Base = {
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
          B = (c.WordArray = A.extend({
            init: function (b, c) {
              b = this.words = b || [];
              this.sigBytes = c != p ? c : 4 * b.length;
            },
            toString: function (b) {
              return (b || D).stringify(this);
            },
            concat: function (b) {
              var c = this.words,
                g = b.words,
                q = this.sigBytes;
              b = b.sigBytes;
              this.clamp();
              if (q % 4)
                for (var h = 0; h < b; h++)
                  c[(q + h) >>> 2] |=
                    ((g[h >>> 2] >>> (24 - (h % 4) * 8)) & 255) <<
                    (24 - ((q + h) % 4) * 8);
              else if (65535 < g.length)
                for (h = 0; h < b; h += 4) c[(q + h) >>> 2] = g[h >>> 2];
              else c.push.apply(c, g);
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
              for (var c = [], g = 0; g < d; g += 4)
                c.push((4294967296 * b.random()) | 0);
              return new B.init(c, d);
            },
          })),
          C = (m.enc = {}),
          D = (C.Hex = {
            stringify: function (b) {
              var c = b.words;
              b = b.sigBytes;
              for (var g = [], h = 0; h < b; h++) {
                var m = (c[h >>> 2] >>> (24 - (h % 4) * 8)) & 255;
                g.push((m >>> 4).toString(16));
                g.push((m & 15).toString(16));
              }
              return g.join("");
            },
            parse: function (b) {
              for (var c = b.length, g = [], h = 0; h < c; h += 2)
                g[h >>> 3] |=
                  parseInt(b.substr(h, 2), 16) << (24 - (h % 8) * 4);
              return new B.init(g, c / 2);
            },
          }),
          g = (C.Latin1 = {
            stringify: function (b) {
              var c = b.words;
              b = b.sigBytes;
              for (var g = [], h = 0; h < b; h++)
                g.push(
                  String.fromCharCode((c[h >>> 2] >>> (24 - (h % 4) * 8)) & 255)
                );
              return g.join("");
            },
            parse: function (b) {
              for (var c = b.length, g = [], h = 0; h < c; h++)
                g[h >>> 2] |= (b.charCodeAt(h) & 255) << (24 - (h % 4) * 8);
              return new B.init(g, c);
            },
          }),
          G = (C.Utf8 = {
            stringify: function (b) {
              try {
                return decodeURIComponent(escape(g.stringify(b)));
              } catch (c) {
                throw Error("Malformed UTF-8 data");
              }
            },
            parse: function (b) {
              return g.parse(unescape(encodeURIComponent(b)));
            },
          }),
          H = (c.BufferedBlockAlgorithm = A.extend({
            reset: function () {
              this._data = new B.init();
              this._nDataBytes = 0;
            },
            _append: function (b) {
              "string" == typeof b && (b = G.parse(b));
              this._data.concat(b);
              this._nDataBytes += b.sigBytes;
            },
            _process: function (d) {
              var c = this._data,
                g = c.words,
                m = c.sigBytes,
                p = this.blockSize,
                y = m / (4 * p),
                y = d ? b.ceil(y) : b.max((y | 0) - this._minBufferSize, 0);
              d = y * p;
              m = b.min(4 * d, m);
              if (d) {
                for (var C = 0; C < d; C += p) this._doProcessBlock(g, C);
                C = g.splice(0, d);
                c.sigBytes -= m;
              }
              return new B.init(C, m);
            },
            clone: function () {
              var b = A.clone.call(this);
              b._data = this._data.clone();
              return b;
            },
            _minBufferSize: 0,
          }));
        c.Hasher = H.extend({
          cfg: A.extend(),
          init: function (b) {
            this.cfg = this.cfg.extend(b);
            this.reset();
          },
          reset: function () {
            H.reset.call(this);
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
            return function (c, g) {
              return new b.init(g).finalize(c);
            };
          },
          _createHmacHelper: function (b) {
            return function (c, g) {
              return new J.HMAC.init(b, g).finalize(c);
            };
          },
        });
        var J = (m.algo = {});
        return m;
      })(Math);
  (function () {
    var h = b,
      p = h.lib,
      m = p.WordArray,
      c = p.Hasher,
      y = [],
      p = (h.algo.SHA1 = c.extend({
        _doReset: function () {
          this._hash = new m.init([
            1732584193, 4023233417, 2562383102, 271733878, 3285377520,
          ]);
        },
        _doProcessBlock: function (b, c) {
          for (
            var h = this._hash.words,
              m = h[0],
              g = h[1],
              p = h[2],
              H = h[3],
              J = h[4],
              d = 0;
            80 > d;
            d++
          ) {
            if (16 > d) y[d] = b[c + d] | 0;
            else {
              var n = y[d - 3] ^ y[d - 8] ^ y[d - 14] ^ y[d - 16];
              y[d] = (n << 1) | (n >>> 31);
            }
            n = ((m << 5) | (m >>> 27)) + J + y[d];
            n =
              20 > d
                ? n + (((g & p) | (~g & H)) + 1518500249)
                : 40 > d
                ? n + ((g ^ p ^ H) + 1859775393)
                : 60 > d
                ? n + (((g & p) | (g & H) | (p & H)) - 1894007588)
                : n + ((g ^ p ^ H) - 899497514);
            J = H;
            H = p;
            p = (g << 30) | (g >>> 2);
            g = m;
            m = n;
          }
          h[0] = (h[0] + m) | 0;
          h[1] = (h[1] + g) | 0;
          h[2] = (h[2] + p) | 0;
          h[3] = (h[3] + H) | 0;
          h[4] = (h[4] + J) | 0;
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
          var b = c.clone.call(this);
          b._hash = this._hash.clone();
          return b;
        },
      }));
    h.SHA1 = c._createHelper(p);
    h.HmacSHA1 = c._createHmacHelper(p);
  })();
  (function () {
    var h = b,
      p = h.enc.Utf8;
    h.algo.HMAC = h.lib.Base.extend({
      init: function (b, c) {
        b = this._hasher = new b.init();
        "string" == typeof c && (c = p.parse(c));
        var h = b.blockSize,
          A = 4 * h;
        c.sigBytes > A && (c = b.finalize(c));
        c.clamp();
        for (
          var B = (this._oKey = c.clone()),
            C = (this._iKey = c.clone()),
            D = B.words,
            g = C.words,
            G = 0;
          G < h;
          G++
        )
          (D[G] ^= 1549556828), (g[G] ^= 909522486);
        B.sigBytes = C.sigBytes = A;
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
      p = h.lib,
      m = p.Base,
      c = p.WordArray,
      p = h.algo,
      y = p.HMAC,
      A = (p.PBKDF2 = m.extend({
        cfg: m.extend({ keySize: 4, hasher: p.SHA1, iterations: 1 }),
        init: function (b) {
          this.cfg = this.cfg.extend(b);
        },
        compute: function (b, h) {
          for (
            var m = this.cfg,
              g = y.create(m.hasher, b),
              p = c.create(),
              A = c.create([1]),
              J = p.words,
              d = A.words,
              n = m.keySize,
              m = m.iterations;
            J.length < n;

          ) {
            var r = g.update(h).finalize(A);
            g.reset();
            for (var q = r.words, z = q.length, F = r, I = 1; I < m; I++) {
              F = g.finalize(F);
              g.reset();
              for (var M = F.words, K = 0; K < z; K++) q[K] ^= M[K];
            }
            p.concat(r);
            d[0]++;
          }
          p.sigBytes = 4 * n;
          return p;
        },
      }));
    h.PBKDF2 = function (b, c, h) {
      return A.create(h).compute(b, c);
    };
  })();
  M.CryptoJS = b;
})(com_sbps_system); /*
 JSEncrypt v2.3.1
 Copyright (c) 2005  Tom Wu
 All Rights Reserved.
 See https://npmcdn.com/jsencrypt@2.3.1/LICENSE.txt
 <a href="http://kjur.github.io/jsrsasign/license/">MIT License</a>
*/
com_sbps_system = com_sbps_system || {};
(function (M, b) {
  "function" === typeof define && define.amd
    ? define(["exports"], b)
    : "object" === typeof exports && "string" !== typeof exports.nodeName
    ? b(module.exports)
    : b(M);
})(com_sbps_system, function (M) {
  function b(a, e, f) {
    null != a &&
      ("number" == typeof a
        ? this.fromNumber(a, e, f)
        : null == e && "string" != typeof a
        ? this.fromString(a, 256)
        : this.fromString(a, e));
  }
  function h() {
    return new b(null);
  }
  function p(a, e, f, b, k, c) {
    for (; 0 <= --c; ) {
      var u = e * this[a++] + f[b] + k;
      k = Math.floor(u / 67108864);
      f[b++] = u & 67108863;
    }
    return k;
  }
  function m(a, e, f, b, k, c) {
    var u = e & 32767;
    for (e >>= 15; 0 <= --c; ) {
      var d = this[a] & 32767,
        g = this[a++] >> 15,
        h = e * d + g * u,
        d = u * d + ((h & 32767) << 15) + f[b] + (k & 1073741823);
      k = (d >>> 30) + (h >>> 15) + e * g + (k >>> 30);
      f[b++] = d & 1073741823;
    }
    return k;
  }
  function c(a, e, f, b, k, c) {
    var u = e & 16383;
    for (e >>= 14; 0 <= --c; ) {
      var d = this[a] & 16383,
        g = this[a++] >> 14,
        h = e * d + g * u,
        d = u * d + ((h & 16383) << 14) + f[b] + k;
      k = (d >> 28) + (h >> 14) + e * g;
      f[b++] = d & 268435455;
    }
    return k;
  }
  function y(a, e) {
    var f = V[a.charCodeAt(e)];
    return null == f ? -1 : f;
  }
  function A(a) {
    var e = h();
    e.fromInt(a);
    return e;
  }
  function B(a) {
    var e = 1,
      f;
    0 != (f = a >>> 16) && ((a = f), (e += 16));
    0 != (f = a >> 8) && ((a = f), (e += 8));
    0 != (f = a >> 4) && ((a = f), (e += 4));
    0 != (f = a >> 2) && ((a = f), (e += 2));
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
  function g(a, e) {
    return a & e;
  }
  function G(a, e) {
    return a | e;
  }
  function H(a, e) {
    return a ^ e;
  }
  function J(a, e) {
    return a & ~e;
  }
  function d() {}
  function n(a) {
    return a;
  }
  function r(a) {
    this.r2 = h();
    this.q3 = h();
    b.ONE.dlShiftTo(2 * a.t, this.r2);
    this.mu = this.r2.divide(a);
    this.m = a;
  }
  function q() {
    this.j = this.i = 0;
    this.S = [];
  }
  function z() {}
  function F(a, e) {
    return new b(a, e);
  }
  function I() {
    this.n = null;
    this.e = 0;
    this.coeff = this.dmq1 = this.dmp1 = this.q = this.p = this.d = null;
  }
  function W(a) {
    var e,
      f,
      b = "";
    for (e = 0; e + 3 <= a.length; e += 3)
      (f = parseInt(a.substring(e, e + 3), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            f >> 6
          ) +
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            f & 63
          ));
    e + 1 == a.length
      ? ((f = parseInt(a.substring(e, e + 1), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            f << 2
          )))
      : e + 2 == a.length &&
        ((f = parseInt(a.substring(e, e + 2), 16)),
        (b +=
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            f >> 2
          ) +
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
            (f & 3) << 4
          )));
    for (; 0 < (b.length & 3); ) b += "=";
    return b;
  }
  function K(a) {
    var e = "",
      f,
      b = 0,
      k;
    for (f = 0; f < a.length && "=" != a.charAt(f); ++f)
      (v =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(
          a.charAt(f)
        )),
        0 > v ||
          (0 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v >> 2)),
              (k = v & 3),
              (b = 1))
            : 1 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(
                (k << 2) | (v >> 4)
              )),
              (k = v & 15),
              (b = 2))
            : 2 == b
            ? ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(k)),
              (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v >> 2)),
              (k = v & 3),
              (b = 3))
            : ((e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(
                (k << 2) | (v >> 4)
              )),
              (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(v & 15)),
              (b = 0)));
    1 == b && (e += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(k << 2));
    return e;
  }
  var N;
  "Microsoft Internet Explorer" == navigator.appName
    ? ((b.prototype.am = m), (N = 30))
    : "Netscape" != navigator.appName
    ? ((b.prototype.am = p), (N = 26))
    : ((b.prototype.am = c), (N = 28));
  b.prototype.DB = N;
  b.prototype.DM = (1 << N) - 1;
  b.prototype.DV = 1 << N;
  b.prototype.FV = Math.pow(2, 52);
  b.prototype.F1 = 52 - N;
  b.prototype.F2 = 2 * N - 52;
  var V = [],
    L;
  N = 48;
  for (L = 0; 9 >= L; ++L) V[N++] = L;
  N = 97;
  for (L = 10; 36 > L; ++L) V[N++] = L;
  N = 65;
  for (L = 10; 36 > L; ++L) V[N++] = L;
  C.prototype.convert = function (a) {
    return 0 > a.s || 0 <= a.compareTo(this.m) ? a.mod(this.m) : a;
  };
  C.prototype.revert = function (a) {
    return a;
  };
  C.prototype.reduce = function (a) {
    a.divRemTo(this.m, null, a);
  };
  C.prototype.mulTo = function (a, e, f) {
    a.multiplyTo(e, f);
    this.reduce(f);
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
      var f = a[e] & 32767,
        b =
          (f * this.mpl +
            (((f * this.mph + (a[e] >> 15) * this.mpl) & this.um) << 15)) &
          a.DM,
        f = e + this.m.t;
      for (a[f] += this.m.am(0, b, a, e, 0, this.m.t); a[f] >= a.DV; )
        (a[f] -= a.DV), a[++f]++;
    }
    a.clamp();
    a.drShiftTo(this.m.t, a);
    0 <= a.compareTo(this.m) && a.subTo(this.m, a);
  };
  D.prototype.mulTo = function (a, e, f) {
    a.multiplyTo(e, f);
    this.reduce(f);
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
    var f;
    if (16 == e) f = 4;
    else if (8 == e) f = 3;
    else if (256 == e) f = 8;
    else if (2 == e) f = 1;
    else if (32 == e) f = 5;
    else if (4 == e) f = 2;
    else {
      this.fromRadix(a, e);
      return;
    }
    this.s = this.t = 0;
    for (var E = a.length, k = !1, c = 0; 0 <= --E; ) {
      var u = 8 == f ? a[E] & 255 : y(a, E);
      0 > u
        ? "-" == a.charAt(E) && (k = !0)
        : ((k = !1),
          0 == c
            ? (this[this.t++] = u)
            : c + f > this.DB
            ? ((this[this.t - 1] |= (u & ((1 << (this.DB - c)) - 1)) << c),
              (this[this.t++] = u >> (this.DB - c)))
            : (this[this.t - 1] |= u << c),
          (c += f),
          c >= this.DB && (c -= this.DB));
    }
    8 == f &&
      0 != (a[0] & 128) &&
      ((this.s = -1),
      0 < c && (this[this.t - 1] |= ((1 << (this.DB - c)) - 1) << c));
    this.clamp();
    k && b.ZERO.subTo(this, this);
  };
  b.prototype.clamp = function () {
    for (var a = this.s & this.DM; 0 < this.t && this[this.t - 1] == a; )
      --this.t;
  };
  b.prototype.dlShiftTo = function (a, e) {
    var f;
    for (f = this.t - 1; 0 <= f; --f) e[f + a] = this[f];
    for (f = a - 1; 0 <= f; --f) e[f] = 0;
    e.t = this.t + a;
    e.s = this.s;
  };
  b.prototype.drShiftTo = function (a, e) {
    for (var f = a; f < this.t; ++f) e[f - a] = this[f];
    e.t = Math.max(this.t - a, 0);
    e.s = this.s;
  };
  b.prototype.lShiftTo = function (a, e) {
    var f = a % this.DB,
      b = this.DB - f,
      k = (1 << b) - 1,
      c = Math.floor(a / this.DB),
      u = (this.s << f) & this.DM,
      d;
    for (d = this.t - 1; 0 <= d; --d)
      (e[d + c + 1] = (this[d] >> b) | u), (u = (this[d] & k) << f);
    for (d = c - 1; 0 <= d; --d) e[d] = 0;
    e[c] = u;
    e.t = this.t + c + 1;
    e.s = this.s;
    e.clamp();
  };
  b.prototype.rShiftTo = function (a, e) {
    e.s = this.s;
    var f = Math.floor(a / this.DB);
    if (f >= this.t) e.t = 0;
    else {
      var b = a % this.DB,
        k = this.DB - b,
        c = (1 << b) - 1;
      e[0] = this[f] >> b;
      for (var d = f + 1; d < this.t; ++d)
        (e[d - f - 1] |= (this[d] & c) << k), (e[d - f] = this[d] >> b);
      0 < b && (e[this.t - f - 1] |= (this.s & c) << k);
      e.t = this.t - f;
      e.clamp();
    }
  };
  b.prototype.subTo = function (a, e) {
    for (var f = 0, b = 0, k = Math.min(a.t, this.t); f < k; )
      (b += this[f] - a[f]), (e[f++] = b & this.DM), (b >>= this.DB);
    if (a.t < this.t) {
      for (b -= a.s; f < this.t; )
        (b += this[f]), (e[f++] = b & this.DM), (b >>= this.DB);
      b += this.s;
    } else {
      for (b += this.s; f < a.t; )
        (b -= a[f]), (e[f++] = b & this.DM), (b >>= this.DB);
      b -= a.s;
    }
    e.s = 0 > b ? -1 : 0;
    -1 > b ? (e[f++] = this.DV + b) : 0 < b && (e[f++] = b);
    e.t = f;
    e.clamp();
  };
  b.prototype.multiplyTo = function (a, e) {
    var f = this.abs(),
      E = a.abs(),
      k = f.t;
    for (e.t = k + E.t; 0 <= --k; ) e[k] = 0;
    for (k = 0; k < E.t; ++k) e[k + f.t] = f.am(0, E[k], e, k, 0, f.t);
    e.s = 0;
    e.clamp();
    this.s != a.s && b.ZERO.subTo(e, e);
  };
  b.prototype.squareTo = function (a) {
    for (var e = this.abs(), f = (a.t = 2 * e.t); 0 <= --f; ) a[f] = 0;
    for (f = 0; f < e.t - 1; ++f) {
      var b = e.am(f, e[f], a, 2 * f, 0, 1);
      (a[f + e.t] += e.am(f + 1, 2 * e[f], a, 2 * f + 1, b, e.t - f - 1)) >=
        e.DV && ((a[f + e.t] -= e.DV), (a[f + e.t + 1] = 1));
    }
    0 < a.t && (a[a.t - 1] += e.am(f, e[f], a, 2 * f, 0, 1));
    a.s = 0;
    a.clamp();
  };
  b.prototype.divRemTo = function (a, e, f) {
    var E = a.abs();
    if (!(0 >= E.t)) {
      var k = this.abs();
      if (k.t < E.t) null != e && e.fromInt(0), null != f && this.copyTo(f);
      else {
        null == f && (f = h());
        var c = h(),
          d = this.s;
        a = a.s;
        var U = this.DB - B(E[E.t - 1]);
        0 < U
          ? (E.lShiftTo(U, c), k.lShiftTo(U, f))
          : (E.copyTo(c), k.copyTo(f));
        E = c.t;
        k = c[E - 1];
        if (0 != k) {
          var g = k * (1 << this.F1) + (1 < E ? c[E - 2] >> this.F2 : 0),
            l = this.FV / g,
            g = (1 << this.F1) / g,
            m = 1 << this.F2,
            n = f.t,
            p = n - E,
            q = null == e ? h() : e;
          c.dlShiftTo(p, q);
          0 <= f.compareTo(q) && ((f[f.t++] = 1), f.subTo(q, f));
          b.ONE.dlShiftTo(E, q);
          for (q.subTo(c, c); c.t < E; ) c[c.t++] = 0;
          for (; 0 <= --p; ) {
            var r =
              f[--n] == k ? this.DM : Math.floor(f[n] * l + (f[n - 1] + m) * g);
            if ((f[n] += c.am(0, r, f, p, 0, E)) < r)
              for (c.dlShiftTo(p, q), f.subTo(q, f); f[n] < --r; )
                f.subTo(q, f);
          }
          null != e && (f.drShiftTo(E, e), d != a && b.ZERO.subTo(e, e));
          f.t = E;
          f.clamp();
          0 < U && f.rShiftTo(U, f);
          0 > d && b.ZERO.subTo(f, f);
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
    var f = h(),
      E = h(),
      k = e.convert(this),
      c = B(a) - 1;
    for (k.copyTo(f); 0 <= --c; )
      if ((e.sqrTo(f, E), 0 < (a & (1 << c)))) e.mulTo(E, k, f);
      else
        var d = f,
          f = E,
          E = d;
    return e.revert(f);
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
      f,
      b = !1,
      k = "",
      c = this.t,
      d = this.DB - ((c * this.DB) % a);
    if (0 < c--)
      for (
        d < this.DB &&
        0 < (f = this[c] >> d) &&
        ((b = !0), (k = "0123456789abcdefghijklmnopqrstuvwxyz".charAt(f)));
        0 <= c;

      )
        d < a
          ? ((f = (this[c] & ((1 << d) - 1)) << (a - d)),
            (f |= this[--c] >> (d += this.DB - a)))
          : ((f = (this[c] >> (d -= a)) & e), 0 >= d && ((d += this.DB), --c)),
          0 < f && (b = !0),
          b && (k += "0123456789abcdefghijklmnopqrstuvwxyz".charAt(f));
    return b ? k : "0";
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
    var f = this.t,
      e = f - a.t;
    if (0 != e) return 0 > this.s ? -e : e;
    for (; 0 <= --f; ) if (0 != (e = this[f] - a[f])) return e;
    return 0;
  };
  b.prototype.bitLength = function () {
    return 0 >= this.t
      ? 0
      : this.DB * (this.t - 1) + B(this[this.t - 1] ^ (this.s & this.DM));
  };
  b.prototype.mod = function (a) {
    var e = h();
    this.abs().divRemTo(a, null, e);
    0 > this.s && 0 < e.compareTo(b.ZERO) && a.subTo(e, e);
    return e;
  };
  b.prototype.modPowInt = function (a, e) {
    var f;
    f = 256 > a || e.isEven() ? new C(e) : new D(e);
    return this.exp(a, f);
  };
  b.ZERO = A(0);
  b.ONE = A(1);
  d.prototype.convert = n;
  d.prototype.revert = n;
  d.prototype.mulTo = function (a, e, f) {
    a.multiplyTo(e, f);
  };
  d.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
  };
  r.prototype.convert = function (a) {
    if (0 > a.s || a.t > 2 * this.m.t) return a.mod(this.m);
    if (0 > a.compareTo(this.m)) return a;
    var e = h();
    a.copyTo(e);
    this.reduce(e);
    return e;
  };
  r.prototype.revert = function (a) {
    return a;
  };
  r.prototype.reduce = function (a) {
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
  r.prototype.mulTo = function (a, e, f) {
    a.multiplyTo(e, f);
    this.reduce(f);
  };
  r.prototype.sqrTo = function (a, e) {
    a.squareTo(e);
    this.reduce(e);
  };
  var O = [
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
    S = 67108864 / O[O.length - 1];
  b.prototype.chunkSize = function (a) {
    return Math.floor((Math.LN2 * this.DB) / Math.log(a));
  };
  b.prototype.toRadix = function (a) {
    null == a && (a = 10);
    if (0 == this.signum() || 2 > a || 36 < a) return "0";
    var e = this.chunkSize(a),
      e = Math.pow(a, e),
      f = A(e),
      b = h(),
      k = h(),
      c = "";
    for (this.divRemTo(f, b, k); 0 < b.signum(); )
      (c = (e + k.intValue()).toString(a).substr(1) + c), b.divRemTo(f, b, k);
    return k.intValue().toString(a) + c;
  };
  b.prototype.fromRadix = function (a, e) {
    this.fromInt(0);
    null == e && (e = 10);
    for (
      var f = this.chunkSize(e),
        c = Math.pow(e, f),
        k = !1,
        d = 0,
        u = 0,
        g = 0;
      g < a.length;
      ++g
    ) {
      var h = y(a, g);
      0 > h
        ? "-" == a.charAt(g) && 0 == this.signum() && (k = !0)
        : ((u = e * u + h),
          ++d >= f && (this.dMultiply(c), this.dAddOffset(u, 0), (u = d = 0)));
    }
    0 < d && (this.dMultiply(Math.pow(e, d)), this.dAddOffset(u, 0));
    k && b.ZERO.subTo(this, this);
  };
  b.prototype.fromNumber = function (a, e, f) {
    if ("number" == typeof e)
      if (2 > a) this.fromInt(1);
      else
        for (
          this.fromNumber(a, f),
            this.testBit(a - 1) ||
              this.bitwiseTo(b.ONE.shiftLeft(a - 1), G, this),
            this.isEven() && this.dAddOffset(1, 0);
          !this.isProbablePrime(e);

        )
          this.dAddOffset(2, 0),
            this.bitLength() > a && this.subTo(b.ONE.shiftLeft(a - 1), this);
    else {
      f = [];
      var c = a & 7;
      f.length = (a >> 3) + 1;
      e.nextBytes(f);
      f[0] = 0 < c ? f[0] & ((1 << c) - 1) : 0;
      this.fromString(f, 256);
    }
  };
  b.prototype.bitwiseTo = function (a, e, b) {
    var c,
      k,
      d = Math.min(a.t, this.t);
    for (c = 0; c < d; ++c) b[c] = e(this[c], a[c]);
    if (a.t < this.t) {
      k = a.s & this.DM;
      for (c = d; c < this.t; ++c) b[c] = e(this[c], k);
      b.t = this.t;
    } else {
      k = this.s & this.DM;
      for (c = d; c < a.t; ++c) b[c] = e(k, a[c]);
      b.t = a.t;
    }
    b.s = e(this.s, a.s);
    b.clamp();
  };
  b.prototype.changeBit = function (a, e) {
    var f = b.ONE.shiftLeft(a);
    this.bitwiseTo(f, e, f);
    return f;
  };
  b.prototype.addTo = function (a, e) {
    for (var b = 0, c = 0, k = Math.min(a.t, this.t); b < k; )
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
    var k;
    for (k = b.t - this.t; c < k; ++c)
      b[c + this.t] = this.am(0, a[c], b, c, 0, this.t);
    for (k = Math.min(a.t, e); c < k; ++c) this.am(0, a[c], b, c, 0, e - c);
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
      f = e.getLowestSetBit();
    if (0 >= f) return !1;
    var c = e.shiftRight(f);
    a = (a + 1) >> 1;
    a > O.length && (a = O.length);
    for (var k = h(), d = 0; d < a; ++d) {
      k.fromInt(O[Math.floor(Math.random() * O.length)]);
      var u = k.modPow(c, this);
      if (0 != u.compareTo(b.ONE) && 0 != u.compareTo(e)) {
        for (var g = 1; g++ < f && 0 != u.compareTo(e); )
          if (((u = u.modPowInt(2, this)), 0 == u.compareTo(b.ONE))) return !1;
        if (0 != u.compareTo(e)) return !1;
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
      k = 0;
    if (0 < a--)
      for (
        b < this.DB &&
        (c = this[a] >> b) != (this.s & this.DM) >> b &&
        (e[k++] = c | (this.s << (this.DB - b)));
        0 <= a;

      )
        if (
          (8 > b
            ? ((c = (this[a] & ((1 << b) - 1)) << (8 - b)),
              (c |= this[--a] >> (b += this.DB - 8)))
            : ((c = (this[a] >> (b -= 8)) & 255),
              0 >= b && ((b += this.DB), --a)),
          0 != (c & 128) && (c |= -256),
          0 == k && (this.s & 128) != (c & 128) && ++k,
          0 < k || c != this.s)
        )
          e[k++] = c;
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
    this.bitwiseTo(a, g, e);
    return e;
  };
  b.prototype.or = function (a) {
    var e = h();
    this.bitwiseTo(a, G, e);
    return e;
  };
  b.prototype.xor = function (a) {
    var e = h();
    this.bitwiseTo(a, H, e);
    return e;
  };
  b.prototype.andNot = function (a) {
    var e = h();
    this.bitwiseTo(a, J, e);
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
    for (var a = 0, b = this.s & this.DM, f = 0; f < this.t; ++f) {
      for (var c = this[f] ^ b, k = 0; 0 != c; ) (c &= c - 1), ++k;
      a += k;
    }
    return a;
  };
  b.prototype.testBit = function (a) {
    var b = Math.floor(a / this.DB);
    return b >= this.t ? 0 != this.s : 0 != (this[b] & (1 << a % this.DB));
  };
  b.prototype.setBit = function (a) {
    return this.changeBit(a, G);
  };
  b.prototype.clearBit = function (a) {
    return this.changeBit(a, J);
  };
  b.prototype.flipBit = function (a) {
    return this.changeBit(a, H);
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
      f = h();
    this.divRemTo(a, b, f);
    return [b, f];
  };
  b.prototype.modPow = function (a, b) {
    var f = a.bitLength(),
      c,
      k = A(1),
      d;
    if (0 >= f) return k;
    c = 18 > f ? 1 : 48 > f ? 3 : 144 > f ? 4 : 768 > f ? 5 : 6;
    d = 8 > f ? new C(b) : b.isEven() ? new r(b) : new D(b);
    var u = [],
      g = 3,
      l = c - 1,
      n = (1 << c) - 1;
    u[1] = d.convert(this);
    if (1 < c)
      for (f = h(), d.sqrTo(u[1], f); g <= n; )
        (u[g] = h()), d.mulTo(f, u[g - 2], u[g]), (g += 2);
    for (var m = a.t - 1, p, q = !0, t = h(), f = B(a[m]) - 1; 0 <= m; ) {
      f >= l
        ? (p = (a[m] >> (f - l)) & n)
        : ((p = (a[m] & ((1 << (f + 1)) - 1)) << (l - f)),
          0 < m && (p |= a[m - 1] >> (this.DB + f - l)));
      for (g = c; 0 == (p & 1); ) (p >>= 1), --g;
      0 > (f -= g) && ((f += this.DB), --m);
      if (q) u[p].copyTo(k), (q = !1);
      else {
        for (; 1 < g; ) d.sqrTo(k, t), d.sqrTo(t, k), (g -= 2);
        0 < g ? d.sqrTo(k, t) : ((g = k), (k = t), (t = g));
        d.mulTo(t, u[p], k);
      }
      for (; 0 <= m && 0 == (a[m] & (1 << f)); )
        d.sqrTo(k, t),
          (g = k),
          (k = t),
          (t = g),
          0 > --f && ((f = this.DB - 1), --m);
    }
    return d.revert(k);
  };
  b.prototype.modInverse = function (a) {
    var e = a.isEven();
    if ((this.isEven() && e) || 0 == a.signum()) return b.ZERO;
    for (
      var f = a.clone(),
        c = this.clone(),
        k = A(1),
        d = A(0),
        u = A(0),
        g = A(1);
      0 != f.signum();

    ) {
      for (; f.isEven(); )
        f.rShiftTo(1, f),
          e
            ? ((k.isEven() && d.isEven()) || (k.addTo(this, k), d.subTo(a, d)),
              k.rShiftTo(1, k))
            : d.isEven() || d.subTo(a, d),
          d.rShiftTo(1, d);
      for (; c.isEven(); )
        c.rShiftTo(1, c),
          e
            ? ((u.isEven() && g.isEven()) || (u.addTo(this, u), g.subTo(a, g)),
              u.rShiftTo(1, u))
            : g.isEven() || g.subTo(a, g),
          g.rShiftTo(1, g);
      0 <= f.compareTo(c)
        ? (f.subTo(c, f), e && k.subTo(u, k), d.subTo(g, d))
        : (c.subTo(f, c), e && u.subTo(k, u), g.subTo(d, g));
    }
    if (0 != c.compareTo(b.ONE)) return b.ZERO;
    if (0 <= g.compareTo(a)) return g.subtract(a);
    if (0 > g.signum()) g.addTo(a, g);
    else return g;
    return 0 > g.signum() ? g.add(a) : g;
  };
  b.prototype.pow = function (a) {
    return this.exp(a, new d());
  };
  b.prototype.gcd = function (a) {
    var b = 0 > this.s ? this.negate() : this.clone();
    a = 0 > a.s ? a.negate() : a.clone();
    if (0 > b.compareTo(a)) {
      var f = b,
        b = a;
      a = f;
    }
    var f = b.getLowestSetBit(),
      c = a.getLowestSetBit();
    if (0 > c) return b;
    f < c && (c = f);
    0 < c && (b.rShiftTo(c, b), a.rShiftTo(c, a));
    for (; 0 < b.signum(); )
      0 < (f = b.getLowestSetBit()) && b.rShiftTo(f, b),
        0 < (f = a.getLowestSetBit()) && a.rShiftTo(f, a),
        0 <= b.compareTo(a)
          ? (b.subTo(a, b), b.rShiftTo(1, b))
          : (a.subTo(b, a), a.rShiftTo(1, a));
    0 < c && a.lShiftTo(c, a);
    return a;
  };
  b.prototype.isProbablePrime = function (a) {
    var b,
      f = this.abs();
    if (1 == f.t && f[0] <= O[O.length - 1]) {
      for (b = 0; b < O.length; ++b) if (f[0] == O[b]) return !0;
      return !1;
    }
    if (f.isEven()) return !1;
    for (b = 1; b < O.length; ) {
      for (var c = O[b], k = b + 1; k < O.length && c < S; ) c *= O[k++];
      for (c = f.modInt(c); b < k; ) if (0 == c % O[b++]) return !1;
    }
    return f.millerRabin(a);
  };
  b.prototype.square = function () {
    var a = h();
    this.squareTo(a);
    return a;
  };
  q.prototype.init = function (a) {
    var b, f, c;
    for (b = 0; 256 > b; ++b) this.S[b] = b;
    for (b = f = 0; 256 > b; ++b)
      (f = (f + this.S[b] + a[b % a.length]) & 255),
        (c = this.S[b]),
        (this.S[b] = this.S[f]),
        (this.S[f] = c);
    this.j = this.i = 0;
  };
  q.prototype.next = function () {
    var a;
    this.i = (this.i + 1) & 255;
    this.j = (this.j + this.S[this.i]) & 255;
    a = this.S[this.i];
    this.S[this.i] = this.S[this.j];
    this.S[this.j] = a;
    return this.S[(a + this.S[this.i]) & 255];
  };
  var R, Q, P;
  if (null == Q) {
    Q = [];
    P = 0;
    if (window.crypto && window.crypto.getRandomValues)
      for (
        L = new Uint32Array(256), window.crypto.getRandomValues(L), N = 0;
        N < L.length;
        ++N
      )
        Q[P++] = L[N] & 255;
    var w = function (a) {
      this.count = this.count || 0;
      if (256 <= this.count || 256 <= P)
        window.removeEventListener
          ? window.removeEventListener("mousemove", w, !1)
          : window.detachEvent && window.detachEvent("onmousemove", w);
      else
        try {
          var b = a.x + a.y;
          Q[P++] = b & 255;
          this.count += 1;
        } catch (f) {}
    };
    window.addEventListener
      ? window.addEventListener("mousemove", w, !1)
      : window.attachEvent && window.attachEvent("onmousemove", w);
  }
  z.prototype.nextBytes = function (a) {
    var b;
    for (b = 0; b < a.length; ++b) {
      var f = b,
        c;
      if (null == R) {
        for (R = new q(); 256 > P; )
          (c = Math.floor(65536 * Math.random())), (Q[P++] = c & 255);
        R.init(Q);
        for (P = 0; P < Q.length; ++P) Q[P] = 0;
        P = 0;
      }
      c = R.next();
      a[f] = c;
    }
  };
  I.prototype.doPublic = function (a) {
    return a.modPowInt(this.e, this.n);
  };
  I.prototype.setPublic = function (a, b) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = F(a, 16)), (this.e = parseInt(b, 16)))
      : console.error("Invalid RSA public key");
  };
  I.prototype.encrypt = function (a) {
    var e;
    e = (this.n.bitLength() + 7) >> 3;
    if (e < a.length + 11)
      console.error("Message too long for RSA"), (e = null);
    else {
      for (var f = [], c = a.length - 1; 0 <= c && 0 < e; ) {
        var k = a.charCodeAt(c--);
        128 > k
          ? (f[--e] = k)
          : 127 < k && 2048 > k
          ? ((f[--e] = (k & 63) | 128), (f[--e] = (k >> 6) | 192))
          : ((f[--e] = (k & 63) | 128),
            (f[--e] = ((k >> 6) & 63) | 128),
            (f[--e] = (k >> 12) | 224));
      }
      f[--e] = 0;
      a = new z();
      for (c = []; 2 < e; ) {
        for (c[0] = 0; 0 == c[0]; ) a.nextBytes(c);
        f[--e] = c[0];
      }
      f[--e] = 2;
      f[--e] = 0;
      e = new b(f);
    }
    if (null == e) return null;
    e = this.doPublic(e);
    if (null == e) return null;
    e = e.toString(16);
    return 0 == (e.length & 1) ? e : "0" + e;
  };
  I.prototype.doPrivate = function (a) {
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
  I.prototype.setPrivate = function (a, b, f) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = F(a, 16)), (this.e = parseInt(b, 16)), (this.d = F(f, 16)))
      : console.error("Invalid RSA private key");
  };
  I.prototype.setPrivateEx = function (a, b, f, c, k, d, u, g) {
    null != a && null != b && 0 < a.length && 0 < b.length
      ? ((this.n = F(a, 16)),
        (this.e = parseInt(b, 16)),
        (this.d = F(f, 16)),
        (this.p = F(c, 16)),
        (this.q = F(k, 16)),
        (this.dmp1 = F(d, 16)),
        (this.dmq1 = F(u, 16)),
        (this.coeff = F(g, 16)))
      : console.error("Invalid RSA private key");
  };
  I.prototype.generate = function (a, e) {
    var f = new z(),
      c = a >> 1;
    this.e = parseInt(e, 16);
    for (var k = new b(e, 16); ; ) {
      for (
        ;
        (this.p = new b(a - c, 1, f)),
          0 != this.p.subtract(b.ONE).gcd(k).compareTo(b.ONE) ||
            !this.p.isProbablePrime(10);

      );
      for (
        ;
        (this.q = new b(c, 1, f)),
          0 != this.q.subtract(b.ONE).gcd(k).compareTo(b.ONE) ||
            !this.q.isProbablePrime(10);

      );
      if (0 >= this.p.compareTo(this.q)) {
        var d = this.p;
        this.p = this.q;
        this.q = d;
      }
      var d = this.p.subtract(b.ONE),
        u = this.q.subtract(b.ONE),
        g = d.multiply(u);
      if (0 == g.gcd(k).compareTo(b.ONE)) {
        this.n = this.p.multiply(this.q);
        this.d = k.modInverse(g);
        this.dmp1 = this.d.mod(d);
        this.dmq1 = this.d.mod(u);
        this.coeff = this.q.modInverse(this.p);
        break;
      }
    }
  };
  I.prototype.decrypt = function (a) {
    a = F(a, 16);
    a = this.doPrivate(a);
    if (null == a) return null;
    a: {
      var b = (this.n.bitLength() + 7) >> 3;
      a = a.toByteArray();
      for (var f = 0; f < a.length && 0 == a[f]; ) ++f;
      if (a.length - f != b - 1 || 2 != a[f]) a = null;
      else {
        for (++f; 0 != a[f]; )
          if (++f >= a.length) {
            a = null;
            break a;
          }
        for (b = ""; ++f < a.length; ) {
          var c = a[f] & 255;
          128 > c
            ? (b += String.fromCharCode(c))
            : 191 < c && 224 > c
            ? ((b += String.fromCharCode(((c & 31) << 6) | (a[f + 1] & 63))),
              ++f)
            : ((b += String.fromCharCode(
                ((c & 15) << 12) | ((a[f + 1] & 63) << 6) | (a[f + 2] & 63)
              )),
              (f += 2));
        }
        a = b;
      }
    }
    return a;
  };
  (function () {
    I.prototype.generateAsync = function (a, e, f) {
      var c = new z(),
        k = a >> 1;
      this.e = parseInt(e, 16);
      var d = new b(e, 16),
        u = this,
        g = function () {
          var e = function () {
              if (0 >= u.p.compareTo(u.q)) {
                var a = u.p;
                u.p = u.q;
                u.q = a;
              }
              var a = u.p.subtract(b.ONE),
                e = u.q.subtract(b.ONE),
                c = a.multiply(e);
              0 == c.gcd(d).compareTo(b.ONE)
                ? ((u.n = u.p.multiply(u.q)),
                  (u.d = d.modInverse(c)),
                  (u.dmp1 = u.d.mod(a)),
                  (u.dmq1 = u.d.mod(e)),
                  (u.coeff = u.q.modInverse(u.p)),
                  setTimeout(function () {
                    f();
                  }, 0))
                : setTimeout(g, 0);
            },
            l = function () {
              u.q = h();
              u.q.fromNumberAsync(k, 1, c, function () {
                u.q.subtract(b.ONE).gcda(d, function (a) {
                  0 == a.compareTo(b.ONE) && u.q.isProbablePrime(10)
                    ? setTimeout(e, 0)
                    : setTimeout(l, 0);
                });
              });
            },
            m = function () {
              u.p = h();
              u.p.fromNumberAsync(a - k, 1, c, function () {
                u.p.subtract(b.ONE).gcda(d, function (a) {
                  0 == a.compareTo(b.ONE) && u.p.isProbablePrime(10)
                    ? setTimeout(l, 0)
                    : setTimeout(m, 0);
                });
              });
            };
          setTimeout(m, 0);
        };
      setTimeout(g, 0);
    };
    b.prototype.gcda = function (a, b) {
      var f = 0 > this.s ? this.negate() : this.clone(),
        c = 0 > a.s ? a.negate() : a.clone();
      if (0 > f.compareTo(c))
        var k = f,
          f = c,
          c = k;
      var d = f.getLowestSetBit(),
        g = c.getLowestSetBit();
      if (0 > g) b(f);
      else {
        d < g && (g = d);
        0 < g && (f.rShiftTo(g, f), c.rShiftTo(g, c));
        var h = function () {
          0 < (d = f.getLowestSetBit()) && f.rShiftTo(d, f);
          0 < (d = c.getLowestSetBit()) && c.rShiftTo(d, c);
          0 <= f.compareTo(c)
            ? (f.subTo(c, f), f.rShiftTo(1, f))
            : (c.subTo(f, c), c.rShiftTo(1, c));
          0 < f.signum()
            ? setTimeout(h, 0)
            : (0 < g && c.lShiftTo(g, c),
              setTimeout(function () {
                b(c);
              }, 0));
        };
        setTimeout(h, 10);
      }
    };
    b.prototype.fromNumberAsync = function (a, e, f, c) {
      if ("number" == typeof e)
        if (2 > a) this.fromInt(1);
        else {
          this.fromNumber(a, f);
          this.testBit(a - 1) ||
            this.bitwiseTo(b.ONE.shiftLeft(a - 1), G, this);
          this.isEven() && this.dAddOffset(1, 0);
          var d = this,
            g = function () {
              d.dAddOffset(2, 0);
              d.bitLength() > a && d.subTo(b.ONE.shiftLeft(a - 1), d);
              d.isProbablePrime(e)
                ? setTimeout(function () {
                    c();
                  }, 0)
                : setTimeout(g, 0);
            };
          setTimeout(g, 0);
        }
      else {
        f = [];
        var u = a & 7;
        f.length = (a >> 3) + 1;
        e.nextBytes(f);
        f[0] = 0 < u ? f[0] & ((1 << u) - 1) : 0;
        this.fromString(f, 256);
      }
    };
  })();
  var l = l || {};
  l.env = l.env || {};
  var x = l,
    t = Object.prototype,
    X = ["toString", "valueOf"];
  l.env.parseUA = function (a) {
    var b = function (a) {
        var b = 0;
        return parseFloat(
          a.replace(/\./g, function () {
            return 1 == b++ ? "" : ".";
          })
        );
      },
      f = navigator,
      f = {
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
        caja: f && f.cajaVersion,
        secure: !1,
        os: null,
      };
    a = a || (navigator && navigator.userAgent);
    var c = window && window.location,
      c = c && c.href;
    f.secure = c && 0 === c.toLowerCase().indexOf("https");
    if (a) {
      /windows|win32/i.test(a)
        ? (f.os = "windows")
        : /macintosh/i.test(a)
        ? (f.os = "macintosh")
        : /rhino/i.test(a) && (f.os = "rhino");
      /KHTML/.test(a) && (f.webkit = 1);
      if ((c = a.match(/AppleWebKit\/([^\s]*)/)) && c[1]) {
        f.webkit = b(c[1]);
        if (/ Mobile\//.test(a))
          (f.mobile = "Apple"),
            (c = a.match(/OS ([^\s]*)/)) &&
              c[1] &&
              (c = b(c[1].replace("_", "."))),
            (f.ios = c),
            (f.ipad = f.ipod = f.iphone = 0),
            (c = a.match(/iPad|iPod|iPhone/)) &&
              c[0] &&
              (f[c[0].toLowerCase()] = f.ios);
        else {
          if ((c = a.match(/NokiaN[^\/]*|Android \d\.\d|webOS\/\d\.\d/)))
            f.mobile = c[0];
          /webOS/.test(a) &&
            ((f.mobile = "WebOS"),
            (c = a.match(/webOS\/([^\s]*);/)) && c[1] && (f.webos = b(c[1])));
          / Android/.test(a) &&
            ((f.mobile = "Android"),
            (c = a.match(/Android ([^\s]*);/)) &&
              c[1] &&
              (f.android = b(c[1])));
        }
        if ((c = a.match(/Chrome\/([^\s]*)/)) && c[1]) f.chrome = b(c[1]);
        else if ((c = a.match(/AdobeAIR\/([^\s]*)/))) f.air = c[0];
      }
      if (!f.webkit)
        if ((c = a.match(/Opera[\s\/]([^\s]*)/)) && c[1]) {
          if (
            ((f.opera = b(c[1])),
            (c = a.match(/Version\/([^\s]*)/)) && c[1] && (f.opera = b(c[1])),
            (c = a.match(/Opera Mini[^;]*/)))
          )
            f.mobile = c[0];
        } else if ((c = a.match(/MSIE\s([^;]*)/)) && c[1]) f.ie = b(c[1]);
        else if ((c = a.match(/Gecko\/([^\s]*)/)))
          (f.gecko = 1),
            (c = a.match(/rv:([^\s\)]*)/)) && c[1] && (f.gecko = b(c[1]));
    }
    return f;
  };
  l.env.ua = l.env.parseUA();
  l.isFunction = function (a) {
    return (
      "function" === typeof a || "[object Function]" === t.toString.apply(a)
    );
  };
  l._IEEnumFix = l.env.ua.ie
    ? function (a, b) {
        var c, d, k;
        for (c = 0; c < X.length; c += 1)
          (d = X[c]), (k = b[d]), x.isFunction(k) && k != t[d] && (a[d] = k);
      }
    : function () {};
  l.extend = function (a, b, c) {
    if (!b || !a)
      throw Error(
        "extend failed, please check that all dependencies are included."
      );
    var d = function () {},
      k;
    d.prototype = b.prototype;
    a.prototype = new d();
    a.prototype.constructor = a;
    a.superclass = b.prototype;
    b.prototype.constructor == t.constructor && (b.prototype.constructor = b);
    if (c) {
      for (k in c) x.hasOwnProperty(c, k) && (a.prototype[k] = c[k]);
      x._IEEnumFix(a.prototype, c);
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
        var f = c.substr(1).length;
        1 == f % 2 ? (f += 1) : c.match(/^[0-7]/) || (f += 2);
        for (var c = "", d = 0; d < f; d++) c += "f";
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
  l.extend(KJUR.asn1.DERAbstractString, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERAbstractTime = function (a) {
    KJUR.asn1.DERAbstractTime.superclass.constructor.call(this);
    this.localDateToUTC = function (a) {
      utc = a.getTime() + 6e4 * a.getTimezoneOffset();
      return new Date(utc);
    };
    this.formatDate = function (a, b) {
      var c = this.zeroPadding,
        d = this.localDateToUTC(a),
        g = String(d.getFullYear());
      "utc" == b && (g = g.substr(2, 2));
      var u = c(String(d.getMonth() + 1), 2),
        h = c(String(d.getDate()), 2),
        l = c(String(d.getHours()), 2),
        m = c(String(d.getMinutes()), 2),
        c = c(String(d.getSeconds()), 2);
      return g + u + h + l + m + c + "Z";
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
    this.setByDateValue = function (a, b, c, d, g, u) {
      a = new Date(Date.UTC(a, b - 1, c, d, g, u, 0));
      this.setByDate(a);
    };
    this.getFreshValueHex = function () {
      return this.hV;
    };
  };
  l.extend(KJUR.asn1.DERAbstractTime, KJUR.asn1.ASN1Object);
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
  l.extend(KJUR.asn1.DERAbstractStructured, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERBoolean = function () {
    KJUR.asn1.DERBoolean.superclass.constructor.call(this);
    this.hT = "01";
    this.hTLV = "0101ff";
  };
  l.extend(KJUR.asn1.DERBoolean, KJUR.asn1.ASN1Object);
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
  l.extend(KJUR.asn1.DERInteger, KJUR.asn1.ASN1Object);
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
        var g = a.substr(c, 8),
          g = parseInt(g, 2).toString(16);
        1 == g.length && (g = "0" + g);
        d += g;
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
  l.extend(KJUR.asn1.DERBitString, KJUR.asn1.ASN1Object);
  KJUR.asn1.DEROctetString = function (a) {
    KJUR.asn1.DEROctetString.superclass.constructor.call(this, a);
    this.hT = "04";
  };
  l.extend(KJUR.asn1.DEROctetString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERNull = function () {
    KJUR.asn1.DERNull.superclass.constructor.call(this);
    this.hT = "05";
    this.hTLV = "0500";
  };
  l.extend(KJUR.asn1.DERNull, KJUR.asn1.ASN1Object);
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
      var k = 40 * parseInt(a[0]) + parseInt(a[1]),
        d = d + c(k);
      a.splice(0, 2);
      for (k = 0; k < a.length; k++) {
        var g = "",
          u = new b(a[k], 10).toString(2),
          h = 7 - (u.length % 7);
        7 == h && (h = 0);
        for (var l = "", m = 0; m < h; m++) l += "0";
        u = l + u;
        for (m = 0; m < u.length - 1; m += 7)
          (h = u.substr(m, 7)),
            m != u.length - 7 && (h = "1" + h),
            (g += c(parseInt(h, 2)));
        d += g;
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
  l.extend(KJUR.asn1.DERObjectIdentifier, KJUR.asn1.ASN1Object);
  KJUR.asn1.DERUTF8String = function (a) {
    KJUR.asn1.DERUTF8String.superclass.constructor.call(this, a);
    this.hT = "0c";
  };
  l.extend(KJUR.asn1.DERUTF8String, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERNumericString = function (a) {
    KJUR.asn1.DERNumericString.superclass.constructor.call(this, a);
    this.hT = "12";
  };
  l.extend(KJUR.asn1.DERNumericString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERPrintableString = function (a) {
    KJUR.asn1.DERPrintableString.superclass.constructor.call(this, a);
    this.hT = "13";
  };
  l.extend(KJUR.asn1.DERPrintableString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERTeletexString = function (a) {
    KJUR.asn1.DERTeletexString.superclass.constructor.call(this, a);
    this.hT = "14";
  };
  l.extend(KJUR.asn1.DERTeletexString, KJUR.asn1.DERAbstractString);
  KJUR.asn1.DERIA5String = function (a) {
    KJUR.asn1.DERIA5String.superclass.constructor.call(this, a);
    this.hT = "16";
  };
  l.extend(KJUR.asn1.DERIA5String, KJUR.asn1.DERAbstractString);
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
  l.extend(KJUR.asn1.DERUTCTime, KJUR.asn1.DERAbstractTime);
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
  l.extend(KJUR.asn1.DERGeneralizedTime, KJUR.asn1.DERAbstractTime);
  KJUR.asn1.DERSequence = function (a) {
    KJUR.asn1.DERSequence.superclass.constructor.call(this, a);
    this.hT = "30";
    this.getFreshValueHex = function () {
      for (var a = "", b = 0; b < this.asn1Array.length; b++)
        a += this.asn1Array[b].getEncodedHex();
      return (this.hV = a);
    };
  };
  l.extend(KJUR.asn1.DERSequence, KJUR.asn1.DERAbstractStructured);
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
  l.extend(KJUR.asn1.DERSet, KJUR.asn1.DERAbstractStructured);
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
  l.extend(KJUR.asn1.DERTaggedObject, KJUR.asn1.ASN1Object);
  (function (a) {
    var b = {},
      c;
    b.decode = function (b) {
      var e;
      if (c === a) {
        var d = "0123456789ABCDEF";
        c = [];
        for (e = 0; 16 > e; ++e) c[d.charAt(e)] = e;
        d = d.toLowerCase();
        for (e = 10; 16 > e; ++e) c[d.charAt(e)] = e;
        for (e = 0; 8 > e; ++e) c[" \f\n\r\tÂ \u2028\u2029".charAt(e)] = -1;
      }
      var d = [],
        g = 0,
        h = 0;
      for (e = 0; e < b.length; ++e) {
        var m = b.charAt(e);
        if ("=" == m) break;
        m = c[m];
        if (-1 != m) {
          if (m === a) throw "Illegal character at offset " + e;
          g |= m;
          2 <= ++h ? ((d[d.length] = g), (h = g = 0)) : (g <<= 4);
        }
      }
      if (h) throw "Hex encoding incomplete: 4 bits missing";
      return d;
    };
    window.Hex = b;
  })();
  (function (a) {
    var b = {},
      c;
    b.decode = function (b) {
      var e;
      if (c === a) {
        c = [];
        for (e = 0; 64 > e; ++e)
          c[
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(
              e
            )
          ] = e;
        for (e = 0; 9 > e; ++e) c["= \f\n\r\tÂ \u2028\u2029".charAt(e)] = -1;
      }
      var d = [],
        g = 0,
        h = 0;
      for (e = 0; e < b.length; ++e) {
        var m = b.charAt(e);
        if ("=" == m) break;
        m = c[m];
        if (-1 != m) {
          if (m === a) throw "Illegal character at offset " + e;
          g |= m;
          4 <= ++h
            ? ((d[d.length] = g >> 16),
              (d[d.length] = (g >> 8) & 255),
              (d[d.length] = g & 255),
              (h = g = 0))
            : (g <<= 6);
        }
      }
      switch (h) {
        case 1:
          throw "Base64 encoding incomplete: at least 2 bits missing";
        case 2:
          d[d.length] = g >> 10;
          break;
        case 3:
          (d[d.length] = g >> 16), (d[d.length] = (g >> 8) & 255);
      }
      return d;
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
    c.hasContent = function (a, d, g) {
      if (a & 32) return !0;
      if (3 > a || 4 < a) return !1;
      var h = new b(g);
      3 == a && h.get();
      if ((h.get() >> 6) & 1) return !1;
      try {
        var m = c.decodeLength(h);
        return h.pos - g.pos + m == d;
      } catch (l) {
        return !1;
      }
    };
    c.decode = function (a) {
      a instanceof b || (a = new b(a, 0));
      var d = new b(a),
        g = a.get(),
        h = c.decodeLength(a),
        m = a.pos - d.pos,
        l = null;
      if (c.hasContent(g, h, a)) {
        var p = a.pos;
        3 == g && a.get();
        l = [];
        if (0 <= h) {
          for (var n = p + h; a.pos < n; ) l[l.length] = c.decode(a);
          if (a.pos != n)
            throw (
              "Content size is not correct for container starting at offset " +
              p
            );
        } else
          try {
            for (;;) {
              n = c.decode(a);
              if (0 === n.tag) break;
              l[l.length] = n;
            }
            h = p - a.pos;
          } catch (q) {
            throw "Exception while decoding undefined length content: " + q;
          }
      } else a.pos += h;
      return new c(d, m, h, g, l);
    };
    c.test = function () {
      for (
        var a = [
            { value: [39], expected: 39 },
            { value: [129, 201], expected: 201 },
            { value: [131, 254, 220, 186], expected: 16702650 },
          ],
          d = 0,
          g = a.length;
        d < g;
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
  I.prototype.parseKey = function (a) {
    try {
      var b = 0,
        c = 0,
        d = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/.test(a)
          ? Hex.decode(a)
          : Base64.unarmor(a),
        g = ASN1.decode(d);
      3 === g.sub.length && (g = g.sub[2].sub[0]);
      if (9 === g.sub.length) {
        b = g.sub[1].getHexStringValue();
        this.n = F(b, 16);
        c = g.sub[2].getHexStringValue();
        this.e = parseInt(c, 16);
        var h = g.sub[3].getHexStringValue();
        this.d = F(h, 16);
        var m = g.sub[4].getHexStringValue();
        this.p = F(m, 16);
        var l = g.sub[5].getHexStringValue();
        this.q = F(l, 16);
        var n = g.sub[6].getHexStringValue();
        this.dmp1 = F(n, 16);
        var p = g.sub[7].getHexStringValue();
        this.dmq1 = F(p, 16);
        var q = g.sub[8].getHexStringValue();
        this.coeff = F(q, 16);
      } else if (2 === g.sub.length) {
        var r = g.sub[1].sub[0],
          b = r.sub[0].getHexStringValue();
        this.n = F(b, 16);
        c = r.sub[1].getHexStringValue();
        this.e = parseInt(c, 16);
      } else return !1;
      return !0;
    } catch (t) {
      return !1;
    }
  };
  I.prototype.getPrivateBaseKey = function () {
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
  I.prototype.getPrivateBaseKeyB64 = function () {
    return W(this.getPrivateBaseKey());
  };
  I.prototype.getPublicBaseKey = function () {
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
  I.prototype.getPublicBaseKeyB64 = function () {
    return W(this.getPublicBaseKey());
  };
  I.prototype.wordwrap = function (a, b) {
    b = b || 64;
    return a
      ? a
          .match(RegExp("(.{1," + b + "})( +|$\n?)|(.{1," + b + "})", "g"))
          .join("\n")
      : a;
  };
  I.prototype.getPrivateKey = function () {
    return (
      "-----BEGIN RSA PRIVATE KEY-----\n" +
      (this.wordwrap(this.getPrivateBaseKeyB64()) + "\n") +
      "-----END RSA PRIVATE KEY-----"
    );
  };
  I.prototype.getPublicKey = function () {
    return (
      "-----BEGIN PUBLIC KEY-----\n" +
      (this.wordwrap(this.getPublicBaseKeyB64()) + "\n") +
      "-----END PUBLIC KEY-----"
    );
  };
  I.prototype.hasPublicKeyProperty = function (a) {
    a = a || {};
    return a.hasOwnProperty("n") && a.hasOwnProperty("e");
  };
  I.prototype.hasPrivateKeyProperty = function (a) {
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
  I.prototype.parsePropertiesFrom = function (a) {
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
    I.call(this);
    a &&
      ("string" === typeof a
        ? this.parseKey(a)
        : (this.hasPrivateKeyProperty(a) || this.hasPublicKeyProperty(a)) &&
          this.parsePropertiesFrom(a));
  };
  T.prototype = new I();
  T.prototype.constructor = T;
  l = function (a) {
    a = a || {};
    this.default_key_size = parseInt(a.default_key_size) || 1024;
    this.default_public_exponent = a.default_public_exponent || "010001";
    this.log = a.log || !1;
    this.key = null;
  };
  l.prototype.setKey = function (a) {
    this.log &&
      this.key &&
      console.warn("A key was already set, overriding existing.");
    this.key = new T(a);
  };
  l.prototype.setPrivateKey = function (a) {
    this.setKey(a);
  };
  l.prototype.setPublicKey = function (a) {
    this.setKey(a);
  };
  l.prototype.decrypt = function (a) {
    try {
      return this.getKey().decrypt(K(a));
    } catch (b) {
      return !1;
    }
  };
  l.prototype.encrypt = function (a) {
    try {
      return W(this.getKey().encrypt(a));
    } catch (b) {
      return !1;
    }
  };
  l.prototype.getKey = function (a) {
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
  l.prototype.getPrivateKey = function () {
    return this.getKey().getPrivateKey();
  };
  l.prototype.getPrivateKeyB64 = function () {
    return this.getKey().getPrivateBaseKeyB64();
  };
  l.prototype.getPublicKey = function () {
    return this.getKey().getPublicKey();
  };
  l.prototype.getPublicKeyB64 = function () {
    return this.getKey().getPublicBaseKeyB64();
  };
  l.version = "2.3.1";
  M.JSEncrypt = l;
});
com_sbps_system = com_sbps_system || {};
(function (M) {
  var b = M.CryptoJS,
    h = M.JSEncrypt;
  M.local = {
    token_url: "https://stbtoken.sps-system.com/token/generateToken",
    pubkey:
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0BMW0T80ZB48dIIEkhcucncJTIthJtKnZN1vh3vfTCbuu7e1OXERSolFa8Me9bTnHqR3y8fXGXXYIxU8BBHBYWbNZWk9wMAn+Hcej8091zYu5BqAlzRxs1S9k6bX/aH24l7qXxzfW6rX71qYuP3v9RRwgnd3tOcWN9wrsIhryTryoC6KSVeh1z/27k1W8uVKCXJniihZ99nUtRSSoST9nZdXDLXyehTBZyZKAWEH5I5wRc3VnjkMUBo5Ksi7G8x0pqLrCgk46Z0YHMpU4M8TORYA1ZyFug7gCOOumfzWiJRBJmctvmwrnfobGC7z/6zSiZH/3YbigZgTsw2073cp0wIDAQAB",
    createUuid: function () {
      var b = "",
        h,
        c;
      for (h = 0; 32 > h; h++) {
        c = (16 * Math.random()) | 0;
        if (8 == h || 12 == h || 16 == h || 20 == h) b += "-";
        b += (12 == h ? 4 : 16 == h ? (c & 3) | 8 : c).toString(16);
      }
      return b;
    },
    encrypt: function (p) {
      var m = p.merchantId,
        c = p.serviceId,
        y = p.ccNumber + ":" + p.ccExpiration + ":" + p.securityCode;
      p = b.lib.WordArray.random(16);
      c = b.PBKDF2(m + c, p, { keySize: 8 });
      m = b.lib.WordArray.random(16);
      y = b.AES.encrypt(y, c, {
        iv: m,
        mode: b.mode.CBC,
        padding: b.pad.Pkcs7,
      });
      y = b.enc.Base64.stringify(y.ciphertext);
      p = b.enc.Base64.stringify(p) + ":" + b.enc.Base64.stringify(m);
      m = new h();
      m.setPublicKey(this.pubkey);
      return { key: m.encrypt(p), value: y };
    },
    createUrl: function (b, h) {
      var c = new Date(),
        c =
          c.getFullYear() +
          "" +
          c.getMonth() +
          1 +
          "" +
          c.getDate() +
          "" +
          c.getHours() +
          "" +
          c.getMinutes() +
          "" +
          c.getSeconds(),
        y = this.encrypt(h);
      return (
        this.token_url +
        "?callback=com_sbps_system.rm['" +
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
        c
      );
    },
    createRequest: function (b, h) {
      return {
        cb: function (b) {
          h(b.tokenRes);
        },
        run: function () {
          var c = document.createElement("script");
          c.charset = "utf8";
          c.src = b;
          document.body.appendChild(c);
        },
      };
    },
  };
  M.rm = {};
  M.generateToken = function (b, h) {
    var c = this.local.createUuid(),
      y = this.local.createUrl(c, b),
      y = this.local.createRequest(y, h);
    this.rm[c] = y;
    y.run();
  };
})(com_sbps_system);
1;
