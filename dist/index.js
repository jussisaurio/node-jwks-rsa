'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

function _interopDefault (ex) { return (ex && (typeof ex === 'object') && 'default' in ex) ? ex['default'] : ex; }

var ms = _interopDefault(require('ms'));
var debug = _interopDefault(require('debug'));
var memoizer = _interopDefault(require('lru-memoizer'));
var limiter = require('limiter');
var request = _interopDefault(require('request'));

function ArgumentError(message) {
  Error.call(this, message);
  Error.captureStackTrace(this, this.constructor);
  this.name = 'ArgumentError';
  this.message = message;
}

ArgumentError.prototype = Object.create(Error.prototype);
ArgumentError.prototype.constructor = ArgumentError;

function JwksError(message) {
  Error.call(this, message);
  Error.captureStackTrace(this, this.constructor);
  this.name = 'JwksError';
  this.message = message;
}

JwksError.prototype = Object.create(Error.prototype);
JwksError.prototype.constructor = JwksError;

function SigningKeyNotFoundError(message) {
  Error.call(this, message);
  Error.captureStackTrace(this, this.constructor);
  this.name = 'SigningKeyNotFoundError';
  this.message = message;
}

SigningKeyNotFoundError.prototype = Object.create(Error.prototype);
SigningKeyNotFoundError.prototype.constructor = SigningKeyNotFoundError;

function certToPEM(cert) {
  cert = cert.match(/.{1,64}/g).join('\n');
  cert = '-----BEGIN CERTIFICATE-----\n' + cert + '\n-----END CERTIFICATE-----\n';
  return cert;
}
function prepadSigned(hexStr) {
  var msb = hexStr[0];
  if (msb < '0' || msb > '7') {
    return '00' + hexStr;
  }
  return hexStr;
}

function toHex(number) {
  var nstr = number.toString(16);
  if (nstr.length % 2) {
    return '0' + nstr;
  }
  return nstr;
}

function encodeLengthHex(n) {
  if (n <= 127) {
    return toHex(n);
  }
  var nHex = toHex(n);
  var lengthOfLengthByte = 128 + nHex.length / 2;
  return toHex(lengthOfLengthByte) + nHex;
}

/*
 * Source: http://stackoverflow.com/questions/18835132/xml-to-pem-in-node-js
 */
function rsaPublicKeyToPEM(modulusB64, exponentB64) {
  var modulus = new Buffer(modulusB64, 'base64');
  var exponent = new Buffer(exponentB64, 'base64');
  var modulusHex = prepadSigned(modulus.toString('hex'));
  var exponentHex = prepadSigned(exponent.toString('hex'));
  var modlen = modulusHex.length / 2;
  var explen = exponentHex.length / 2;

  var encodedModlen = encodeLengthHex(modlen);
  var encodedExplen = encodeLengthHex(explen);
  var encodedPubkey = '30' + encodeLengthHex(modlen + explen + encodedModlen.length / 2 + encodedExplen.length / 2 + 2) + '02' + encodedModlen + modulusHex + '02' + encodedExplen + exponentHex;

  var der = new Buffer(encodedPubkey, 'hex').toString('base64');

  var pem = '-----BEGIN RSA PUBLIC KEY-----\n';
  pem += '' + der.match(/.{1,64}/g).join('\n');
  pem += '\n-----END RSA PUBLIC KEY-----\n';
  return pem;
}

function cacheSigningKey (client) {
  var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : options,
      _ref$cacheMaxEntries = _ref.cacheMaxEntries,
      cacheMaxEntries = _ref$cacheMaxEntries === undefined ? 5 : _ref$cacheMaxEntries,
      _ref$cacheMaxAge = _ref.cacheMaxAge,
      cacheMaxAge = _ref$cacheMaxAge === undefined ? ms('10h') : _ref$cacheMaxAge;

  var logger = debug('jwks');
  var getSigningKey = client.getSigningKey;

  logger('Configured caching of singing keys. Max: ' + cacheMaxEntries + ' / Age: ' + cacheMaxAge);
  return memoizer({
    load: function load(kid, callback) {
      getSigningKey(kid, function (err, key) {
        if (err) {
          return callback(err);
        }

        logger('Caching signing key for \'' + kid + '\':', key);
        return callback(null, key);
      });
    },
    hash: function hash(kid) {
      return kid;
    },
    maxAge: cacheMaxAge,
    max: cacheMaxEntries
  });
}

function JwksRateLimitError(message) {
  Error.call(this, message);
  Error.captureStackTrace(this, this.constructor);
  this.name = 'JwksRateLimitError';
  this.message = message;
}

JwksRateLimitError.prototype = Object.create(Error.prototype);
JwksRateLimitError.prototype.constructor = JwksRateLimitError;

function rateLimitSigningKey (client) {
  var _ref = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : options,
      _ref$jwksRequestsPerM = _ref.jwksRequestsPerMinute,
      jwksRequestsPerMinute = _ref$jwksRequestsPerM === undefined ? 10 : _ref$jwksRequestsPerM;

  var logger = debug('jwks');
  var getSigningKey = client.getSigningKey;

  var limiter$$1 = new limiter.RateLimiter(jwksRequestsPerMinute, 'minute', true);
  logger('Configured rate limiting to JWKS endpoint at ' + jwksRequestsPerMinute + '/minute');

  return function (kid, cb) {
    limiter$$1.removeTokens(1, function (err, remaining) {
      if (err) {
        return cb(err);
      }

      logger('Requests to the JWKS endpoint available for the next minute:', remaining);
      if (remaining < 0) {
        logger('Too many requests to the JWKS endpoint');
        return cb(new JwksRateLimitError('Too many requests to the JWKS endpoint'));
      } else {
        return getSigningKey(kid, cb);
      }
    });
  };
}

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var JwksClient = function () {
  function JwksClient(options) {
    var _this = this;

    _classCallCheck(this, JwksClient);

    this.getSigningKey = function (kid, cb) {
      _this.logger('Fetching signing key for \'' + kid + '\'');

      _this.getSigningKeys(function (err, keys) {
        if (err) {
          return cb(err);
        }

        var key = keys.find(function (k) {
          return k.kid === kid;
        });
        if (key) {
          return cb(null, key);
        } else {
          _this.logger('Unable to find a signing key that matches \'' + kid + '\'');
          return cb(new SigningKeyNotFoundError('Unable to find a signing key that matches \'' + kid + '\''));
        }
      });
    };

    this.options = Object.assign({ rateLimit: false, cache: false, strictSsl: true }, options);
    this.logger = function () {};

    // Initialize wrappers.
    if (this.options.rateLimit) {
      this.getSigningKey = rateLimitSigningKey(this, options);
    }
    if (this.options.cache) {
      this.getSigningKey = cacheSigningKey(this, options);
    }
  }

  _createClass(JwksClient, [{
    key: 'getKeys',
    value: function getKeys(cb) {
      var _this2 = this;

      this.logger('Fetching keys from \'' + this.options.jwksUri + '\'');
      request({ json: true, uri: this.options.jwksUri, strictSSL: this.options.strictSsl }, function (err, res) {
        if (err || res.statusCode < 200 || res.statusCode >= 300) {
          _this2.logger('Failure:', res && res.body || err);
          if (res) {
            return cb(new JwksError(res.body && (res.body.message || res.body) || res.statusMessage || 'Http Error ' + res.statusCode));
          }
          return cb(err);
        }

        var keys = _this2.options.keyInResponseBody ? [res.body] : res.body.keys;
        _this2.logger('Keys:', keys);
        return cb(null, keys);
      });
    }
  }, {
    key: 'getSigningKeys',
    value: function getSigningKeys(cb) {
      var _this3 = this;

      this.getKeys(function (err, keys) {
        if (err) {
          return cb(err);
        }

        if (!keys || !keys.length) {
          return cb(new JwksError('The JWKS endpoint did not contain any keys'));
        }

        var signingKeys = keys.filter(function (key) {
          return key.use === 'sig' && key.kty === 'RSA' && key.kid && (key.x5c && key.x5c.length || key.n && key.e);
        }).map(function (key) {
          if (key.x5c && key.x5c.length) {
            return { kid: key.kid, nbf: key.nbf, publicKey: certToPEM(key.x5c[0]) };
          } else {
            return { kid: key.kid, nbf: key.nbf, rsaPublicKey: rsaPublicKeyToPEM(key.n, key.e) };
          }
        });

        if (!signingKeys.length) {
          return cb(new JwksError('The JWKS endpoint did not contain any signing keys'));
        }

        _this3.logger('Signing Keys:', signingKeys);
        return cb(null, signingKeys);
      });
    }
  }]);

  return JwksClient;
}();

var handleSigningKeyError = function handleSigningKeyError(err, cb) {
  // If we didn't find a match, can't provide a key.
  if (err && err.name === 'SigningKeyNotFoundError') {
    return cb(null, null, null);
  }

  // If an error occured like rate limiting or HTTP issue, we'll bubble up the error.
  if (err) {
    return cb(err, null, null);
  }
};

/**
 * Call hapiJwt2Key as a Promise
 * @param {object} options 
 * @returns {Promise}
 */
var hapiJwt2KeyAsync = function hapiJwt2KeyAsync(options) {
  var secretProvider = module.exports.hapiJwt2Key(options);
  return function (decoded) {
    return new Promise(function (resolve, reject) {
      var cb = function cb(err, key) {
        !key || err ? reject(err) : resolve({ key: key });
      };
      secretProvider(decoded, cb);
    });
  };
};

var hapiJwt2Key = function hapiJwt2Key(options) {
  if (options === null || options === undefined) {
    throw new ArgumentError('An options object must be provided when initializing hapiJwt2Key');
  }

  var client = new JwksClient(options);
  var onError = options.handleSigningKeyError || handleSigningKeyError;

  return function secretProvider(decoded, cb) {
    // We cannot find a signing certificate if there is no header (no kid).
    if (!decoded || !decoded.header) {
      return cb(null, null, null);
    }

    // Only RS256 is supported.
    if (decoded.header.alg !== 'RS256') {
      return cb(null, null, null);
    }

    client.getSigningKey(decoded.header.kid, function (err, key) {
      if (err) {
        return onError(err, function (newError) {
          return cb(newError, null, null);
        });
      }

      // Provide the key.
      return cb(null, key.publicKey || key.rsaPublicKey, key);
    });
  };
};

var handleSigningKeyError$1 = function handleSigningKeyError(err, cb) {
  // If we didn't find a match, can't provide a key.
  if (err && err.name === 'SigningKeyNotFoundError') {
    return cb(null);
  }

  // If an error occured like rate limiting or HTTP issue, we'll bubble up the error.
  if (err) {
    return cb(err);
  }
};

var expressJwtSecret = function expressJwtSecret(options) {
  if (options === null || options === undefined) {
    throw new ArgumentError('An options object must be provided when initializing expressJwtSecret');
  }

  var client = new JwksClient(options);
  var onError = options.handleSigningKeyError || handleSigningKeyError$1;

  return function secretProvider(req, header, payload, cb) {
    // Only RS256 is supported.
    if (!header || header.alg !== 'RS256') {
      return cb(null, null);
    }

    client.getSigningKey(header.kid, function (err, key) {
      if (err) {
        return onError(err, function (newError) {
          return cb(newError, null);
        });
      }

      // Provide the key.
      return cb(null, key.publicKey || key.rsaPublicKey);
    });
  };
};

var koaJwtSecret = function koaJwtSecret() {
  var options = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};


  if (!options.jwksUri) {
    throw new ArgumentError('No JWKS URI provided');
  }

  var client = new JwksClient(options);

  return function secretProvider() {
    var _ref = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {},
        alg = _ref.alg,
        kid = _ref.kid;

    return new Promise(function (resolve, reject) {

      // Only RS256 is supported.
      if (alg !== 'RS256') {
        return reject(new Error('Missing / invalid token algorithm'));
      }

      client.getSigningKey(kid, function (err, key) {
        if (err) {

          if (options.handleSigningKeyError) {
            return options.handleSigningKeyError(err).then(reject);
          }

          return reject(err);
        }

        // Provide the key.
        resolve(key.publicKey || key.rsaPublicKey);
      });
    });
  };
};

var index = (function (options) {
  return new JwksClient(options);
});

var ArgumentError$1 = ArgumentError;
var JwksError$1 = JwksError;
var JwksRateLimitError$1 = JwksRateLimitError;
var SigningKeyNotFoundError$1 = SigningKeyNotFoundError;

var expressJwtSecret$1 = expressJwtSecret;
var hapiJwt2Key$1 = hapiJwt2Key;
var hapiJwt2KeyAsync$1 = hapiJwt2KeyAsync;
var koaJwtSecret$1 = koaJwtSecret;

exports.default = index;
exports.ArgumentError = ArgumentError$1;
exports.JwksError = JwksError$1;
exports.JwksRateLimitError = JwksRateLimitError$1;
exports.SigningKeyNotFoundError = SigningKeyNotFoundError$1;
exports.expressJwtSecret = expressJwtSecret$1;
exports.hapiJwt2Key = hapiJwt2Key$1;
exports.hapiJwt2KeyAsync = hapiJwt2KeyAsync$1;
exports.koaJwtSecret = koaJwtSecret$1;
