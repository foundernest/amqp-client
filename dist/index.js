import require$$1$1 from 'querystring';
import require$$0 from 'assert';
import require$$3 from 'stream';
import require$$0$1 from 'events';
import require$$1 from 'util';
import require$$6 from 'net';
import require$$7 from 'tls';

var commonjsGlobal = typeof globalThis !== 'undefined' ? globalThis : typeof window !== 'undefined' ? window : typeof global !== 'undefined' ? global : typeof self !== 'undefined' ? self : {};

var connect$2 = {};

/**
 * Check if we're required to add a port number.
 *
 * @see https://url.spec.whatwg.org/#default-port
 * @param {Number|String} port Port number we need to check
 * @param {String} protocol Protocol we need to check against.
 * @returns {Boolean} Is it a default port for the given protocol
 * @api private
 */
var requiresPort = function required(port, protocol) {
  protocol = protocol.split(':')[0];
  port = +port;

  if (!port) return false;

  switch (protocol) {
    case 'http':
    case 'ws':
    return port !== 80;

    case 'https':
    case 'wss':
    return port !== 443;

    case 'ftp':
    return port !== 21;

    case 'gopher':
    return port !== 70;

    case 'file':
    return false;
  }

  return port !== 0;
};

var querystringify$1 = {};

var has = Object.prototype.hasOwnProperty
  , undef;

/**
 * Decode a URI encoded string.
 *
 * @param {String} input The URI encoded string.
 * @returns {String|Null} The decoded string.
 * @api private
 */
function decode$1(input) {
  try {
    return decodeURIComponent(input.replace(/\+/g, ' '));
  } catch (e) {
    return null;
  }
}

/**
 * Attempts to encode a given input.
 *
 * @param {String} input The string that needs to be encoded.
 * @returns {String|Null} The encoded string.
 * @api private
 */
function encode(input) {
  try {
    return encodeURIComponent(input);
  } catch (e) {
    return null;
  }
}

/**
 * Simple query string parser.
 *
 * @param {String} query The query string that needs to be parsed.
 * @returns {Object}
 * @api public
 */
function querystring(query) {
  var parser = /([^=?#&]+)=?([^&]*)/g
    , result = {}
    , part;

  while (part = parser.exec(query)) {
    var key = decode$1(part[1])
      , value = decode$1(part[2]);

    //
    // Prevent overriding of existing properties. This ensures that build-in
    // methods like `toString` or __proto__ are not overriden by malicious
    // querystrings.
    //
    // In the case if failed decoding, we want to omit the key/value pairs
    // from the result.
    //
    if (key === null || value === null || key in result) continue;
    result[key] = value;
  }

  return result;
}

/**
 * Transform a query string to an object.
 *
 * @param {Object} obj Object that should be transformed.
 * @param {String} prefix Optional prefix.
 * @returns {String}
 * @api public
 */
function querystringify(obj, prefix) {
  prefix = prefix || '';

  var pairs = []
    , value
    , key;

  //
  // Optionally prefix with a '?' if needed
  //
  if ('string' !== typeof prefix) prefix = '?';

  for (key in obj) {
    if (has.call(obj, key)) {
      value = obj[key];

      //
      // Edge cases where we actually want to encode the value to an empty
      // string instead of the stringified value.
      //
      if (!value && (value === null || value === undef || isNaN(value))) {
        value = '';
      }

      key = encode(key);
      value = encode(value);

      //
      // If we failed to encode the strings, we should bail out as we don't
      // want to add invalid strings to the query.
      //
      if (key === null || value === null) continue;
      pairs.push(key +'='+ value);
    }
  }

  return pairs.length ? prefix + pairs.join('&') : '';
}

//
// Expose the module.
//
querystringify$1.stringify = querystringify;
querystringify$1.parse = querystring;

var required = requiresPort
  , qs = querystringify$1
  , controlOrWhitespace = /^[\x00-\x20\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/
  , CRHTLF = /[\n\r\t]/g
  , slashes = /^[A-Za-z][A-Za-z0-9+-.]*:\/\//
  , port = /:\d+$/
  , protocolre = /^([a-z][a-z0-9.+-]*:)?(\/\/)?([\\/]+)?([\S\s]*)/i
  , windowsDriveLetter = /^[a-zA-Z]:/;

/**
 * Remove control characters and whitespace from the beginning of a string.
 *
 * @param {Object|String} str String to trim.
 * @returns {String} A new string representing `str` stripped of control
 *     characters and whitespace from its beginning.
 * @public
 */
function trimLeft(str) {
  return (str ? str : '').toString().replace(controlOrWhitespace, '');
}

/**
 * These are the parse rules for the URL parser, it informs the parser
 * about:
 *
 * 0. The char it Needs to parse, if it's a string it should be done using
 *    indexOf, RegExp using exec and NaN means set as current value.
 * 1. The property we should set when parsing this value.
 * 2. Indication if it's backwards or forward parsing, when set as number it's
 *    the value of extra chars that should be split off.
 * 3. Inherit from location if non existing in the parser.
 * 4. `toLowerCase` the resulting value.
 */
var rules = [
  ['#', 'hash'],                        // Extract from the back.
  ['?', 'query'],                       // Extract from the back.
  function sanitize(address, url) {     // Sanitize what is left of the address
    return isSpecial(url.protocol) ? address.replace(/\\/g, '/') : address;
  },
  ['/', 'pathname'],                    // Extract from the back.
  ['@', 'auth', 1],                     // Extract from the front.
  [NaN, 'host', undefined, 1, 1],       // Set left over value.
  [/:(\d*)$/, 'port', undefined, 1],    // RegExp the back.
  [NaN, 'hostname', undefined, 1, 1]    // Set left over.
];

/**
 * These properties should not be copied or inherited from. This is only needed
 * for all non blob URL's as a blob URL does not include a hash, only the
 * origin.
 *
 * @type {Object}
 * @private
 */
var ignore = { hash: 1, query: 1 };

/**
 * The location object differs when your code is loaded through a normal page,
 * Worker or through a worker using a blob. And with the blobble begins the
 * trouble as the location object will contain the URL of the blob, not the
 * location of the page where our code is loaded in. The actual origin is
 * encoded in the `pathname` so we can thankfully generate a good "default"
 * location from it so we can generate proper relative URL's again.
 *
 * @param {Object|String} loc Optional default location object.
 * @returns {Object} lolcation object.
 * @public
 */
function lolcation(loc) {
  var globalVar;

  if (typeof window !== 'undefined') globalVar = window;
  else if (typeof commonjsGlobal !== 'undefined') globalVar = commonjsGlobal;
  else if (typeof self !== 'undefined') globalVar = self;
  else globalVar = {};

  var location = globalVar.location || {};
  loc = loc || location;

  var finaldestination = {}
    , type = typeof loc
    , key;

  if ('blob:' === loc.protocol) {
    finaldestination = new Url(unescape(loc.pathname), {});
  } else if ('string' === type) {
    finaldestination = new Url(loc, {});
    for (key in ignore) delete finaldestination[key];
  } else if ('object' === type) {
    for (key in loc) {
      if (key in ignore) continue;
      finaldestination[key] = loc[key];
    }

    if (finaldestination.slashes === undefined) {
      finaldestination.slashes = slashes.test(loc.href);
    }
  }

  return finaldestination;
}

/**
 * Check whether a protocol scheme is special.
 *
 * @param {String} The protocol scheme of the URL
 * @return {Boolean} `true` if the protocol scheme is special, else `false`
 * @private
 */
function isSpecial(scheme) {
  return (
    scheme === 'file:' ||
    scheme === 'ftp:' ||
    scheme === 'http:' ||
    scheme === 'https:' ||
    scheme === 'ws:' ||
    scheme === 'wss:'
  );
}

/**
 * @typedef ProtocolExtract
 * @type Object
 * @property {String} protocol Protocol matched in the URL, in lowercase.
 * @property {Boolean} slashes `true` if protocol is followed by "//", else `false`.
 * @property {String} rest Rest of the URL that is not part of the protocol.
 */

/**
 * Extract protocol information from a URL with/without double slash ("//").
 *
 * @param {String} address URL we want to extract from.
 * @param {Object} location
 * @return {ProtocolExtract} Extracted information.
 * @private
 */
function extractProtocol(address, location) {
  address = trimLeft(address);
  address = address.replace(CRHTLF, '');
  location = location || {};

  var match = protocolre.exec(address);
  var protocol = match[1] ? match[1].toLowerCase() : '';
  var forwardSlashes = !!match[2];
  var otherSlashes = !!match[3];
  var slashesCount = 0;
  var rest;

  if (forwardSlashes) {
    if (otherSlashes) {
      rest = match[2] + match[3] + match[4];
      slashesCount = match[2].length + match[3].length;
    } else {
      rest = match[2] + match[4];
      slashesCount = match[2].length;
    }
  } else {
    if (otherSlashes) {
      rest = match[3] + match[4];
      slashesCount = match[3].length;
    } else {
      rest = match[4];
    }
  }

  if (protocol === 'file:') {
    if (slashesCount >= 2) {
      rest = rest.slice(2);
    }
  } else if (isSpecial(protocol)) {
    rest = match[4];
  } else if (protocol) {
    if (forwardSlashes) {
      rest = rest.slice(2);
    }
  } else if (slashesCount >= 2 && isSpecial(location.protocol)) {
    rest = match[4];
  }

  return {
    protocol: protocol,
    slashes: forwardSlashes || isSpecial(protocol),
    slashesCount: slashesCount,
    rest: rest
  };
}

/**
 * Resolve a relative URL pathname against a base URL pathname.
 *
 * @param {String} relative Pathname of the relative URL.
 * @param {String} base Pathname of the base URL.
 * @return {String} Resolved pathname.
 * @private
 */
function resolve(relative, base) {
  if (relative === '') return base;

  var path = (base || '/').split('/').slice(0, -1).concat(relative.split('/'))
    , i = path.length
    , last = path[i - 1]
    , unshift = false
    , up = 0;

  while (i--) {
    if (path[i] === '.') {
      path.splice(i, 1);
    } else if (path[i] === '..') {
      path.splice(i, 1);
      up++;
    } else if (up) {
      if (i === 0) unshift = true;
      path.splice(i, 1);
      up--;
    }
  }

  if (unshift) path.unshift('');
  if (last === '.' || last === '..') path.push('');

  return path.join('/');
}

/**
 * The actual URL instance. Instead of returning an object we've opted-in to
 * create an actual constructor as it's much more memory efficient and
 * faster and it pleases my OCD.
 *
 * It is worth noting that we should not use `URL` as class name to prevent
 * clashes with the global URL instance that got introduced in browsers.
 *
 * @constructor
 * @param {String} address URL we want to parse.
 * @param {Object|String} [location] Location defaults for relative paths.
 * @param {Boolean|Function} [parser] Parser for the query string.
 * @private
 */
function Url(address, location, parser) {
  address = trimLeft(address);
  address = address.replace(CRHTLF, '');

  if (!(this instanceof Url)) {
    return new Url(address, location, parser);
  }

  var relative, extracted, parse, instruction, index, key
    , instructions = rules.slice()
    , type = typeof location
    , url = this
    , i = 0;

  //
  // The following if statements allows this module two have compatibility with
  // 2 different API:
  //
  // 1. Node.js's `url.parse` api which accepts a URL, boolean as arguments
  //    where the boolean indicates that the query string should also be parsed.
  //
  // 2. The `URL` interface of the browser which accepts a URL, object as
  //    arguments. The supplied object will be used as default values / fall-back
  //    for relative paths.
  //
  if ('object' !== type && 'string' !== type) {
    parser = location;
    location = null;
  }

  if (parser && 'function' !== typeof parser) parser = qs.parse;

  location = lolcation(location);

  //
  // Extract protocol information before running the instructions.
  //
  extracted = extractProtocol(address || '', location);
  relative = !extracted.protocol && !extracted.slashes;
  url.slashes = extracted.slashes || relative && location.slashes;
  url.protocol = extracted.protocol || location.protocol || '';
  address = extracted.rest;

  //
  // When the authority component is absent the URL starts with a path
  // component.
  //
  if (
    extracted.protocol === 'file:' && (
      extracted.slashesCount !== 2 || windowsDriveLetter.test(address)) ||
    (!extracted.slashes &&
      (extracted.protocol ||
        extracted.slashesCount < 2 ||
        !isSpecial(url.protocol)))
  ) {
    instructions[3] = [/(.*)/, 'pathname'];
  }

  for (; i < instructions.length; i++) {
    instruction = instructions[i];

    if (typeof instruction === 'function') {
      address = instruction(address, url);
      continue;
    }

    parse = instruction[0];
    key = instruction[1];

    if (parse !== parse) {
      url[key] = address;
    } else if ('string' === typeof parse) {
      index = parse === '@'
        ? address.lastIndexOf(parse)
        : address.indexOf(parse);

      if (~index) {
        if ('number' === typeof instruction[2]) {
          url[key] = address.slice(0, index);
          address = address.slice(index + instruction[2]);
        } else {
          url[key] = address.slice(index);
          address = address.slice(0, index);
        }
      }
    } else if ((index = parse.exec(address))) {
      url[key] = index[1];
      address = address.slice(0, index.index);
    }

    url[key] = url[key] || (
      relative && instruction[3] ? location[key] || '' : ''
    );

    //
    // Hostname, host and protocol should be lowercased so they can be used to
    // create a proper `origin`.
    //
    if (instruction[4]) url[key] = url[key].toLowerCase();
  }

  //
  // Also parse the supplied query string in to an object. If we're supplied
  // with a custom parser as function use that instead of the default build-in
  // parser.
  //
  if (parser) url.query = parser(url.query);

  //
  // If the URL is relative, resolve the pathname against the base URL.
  //
  if (
      relative
    && location.slashes
    && url.pathname.charAt(0) !== '/'
    && (url.pathname !== '' || location.pathname !== '')
  ) {
    url.pathname = resolve(url.pathname, location.pathname);
  }

  //
  // Default to a / for pathname if none exists. This normalizes the URL
  // to always have a /
  //
  if (url.pathname.charAt(0) !== '/' && isSpecial(url.protocol)) {
    url.pathname = '/' + url.pathname;
  }

  //
  // We should not add port numbers if they are already the default port number
  // for a given protocol. As the host also contains the port number we're going
  // override it with the hostname which contains no port number.
  //
  if (!required(url.port, url.protocol)) {
    url.host = url.hostname;
    url.port = '';
  }

  //
  // Parse down the `auth` for the username and password.
  //
  url.username = url.password = '';

  if (url.auth) {
    index = url.auth.indexOf(':');

    if (~index) {
      url.username = url.auth.slice(0, index);
      url.username = encodeURIComponent(decodeURIComponent(url.username));

      url.password = url.auth.slice(index + 1);
      url.password = encodeURIComponent(decodeURIComponent(url.password));
    } else {
      url.username = encodeURIComponent(decodeURIComponent(url.auth));
    }

    url.auth = url.password ? url.username +':'+ url.password : url.username;
  }

  url.origin = url.protocol !== 'file:' && isSpecial(url.protocol) && url.host
    ? url.protocol +'//'+ url.host
    : 'null';

  //
  // The href is just the compiled result.
  //
  url.href = url.toString();
}

/**
 * This is convenience method for changing properties in the URL instance to
 * insure that they all propagate correctly.
 *
 * @param {String} part          Property we need to adjust.
 * @param {Mixed} value          The newly assigned value.
 * @param {Boolean|Function} fn  When setting the query, it will be the function
 *                               used to parse the query.
 *                               When setting the protocol, double slash will be
 *                               removed from the final url if it is true.
 * @returns {URL} URL instance for chaining.
 * @public
 */
function set(part, value, fn) {
  var url = this;

  switch (part) {
    case 'query':
      if ('string' === typeof value && value.length) {
        value = (fn || qs.parse)(value);
      }

      url[part] = value;
      break;

    case 'port':
      url[part] = value;

      if (!required(value, url.protocol)) {
        url.host = url.hostname;
        url[part] = '';
      } else if (value) {
        url.host = url.hostname +':'+ value;
      }

      break;

    case 'hostname':
      url[part] = value;

      if (url.port) value += ':'+ url.port;
      url.host = value;
      break;

    case 'host':
      url[part] = value;

      if (port.test(value)) {
        value = value.split(':');
        url.port = value.pop();
        url.hostname = value.join(':');
      } else {
        url.hostname = value;
        url.port = '';
      }

      break;

    case 'protocol':
      url.protocol = value.toLowerCase();
      url.slashes = !fn;
      break;

    case 'pathname':
    case 'hash':
      if (value) {
        var char = part === 'pathname' ? '/' : '#';
        url[part] = value.charAt(0) !== char ? char + value : value;
      } else {
        url[part] = value;
      }
      break;

    case 'username':
    case 'password':
      url[part] = encodeURIComponent(value);
      break;

    case 'auth':
      var index = value.indexOf(':');

      if (~index) {
        url.username = value.slice(0, index);
        url.username = encodeURIComponent(decodeURIComponent(url.username));

        url.password = value.slice(index + 1);
        url.password = encodeURIComponent(decodeURIComponent(url.password));
      } else {
        url.username = encodeURIComponent(decodeURIComponent(value));
      }
  }

  for (var i = 0; i < rules.length; i++) {
    var ins = rules[i];

    if (ins[4]) url[ins[1]] = url[ins[1]].toLowerCase();
  }

  url.auth = url.password ? url.username +':'+ url.password : url.username;

  url.origin = url.protocol !== 'file:' && isSpecial(url.protocol) && url.host
    ? url.protocol +'//'+ url.host
    : 'null';

  url.href = url.toString();

  return url;
}

/**
 * Transform the properties back in to a valid and full URL string.
 *
 * @param {Function} stringify Optional query stringify function.
 * @returns {String} Compiled version of the URL.
 * @public
 */
function toString(stringify) {
  if (!stringify || 'function' !== typeof stringify) stringify = qs.stringify;

  var query
    , url = this
    , host = url.host
    , protocol = url.protocol;

  if (protocol && protocol.charAt(protocol.length - 1) !== ':') protocol += ':';

  var result =
    protocol +
    ((url.protocol && url.slashes) || isSpecial(url.protocol) ? '//' : '');

  if (url.username) {
    result += url.username;
    if (url.password) result += ':'+ url.password;
    result += '@';
  } else if (url.password) {
    result += ':'+ url.password;
    result += '@';
  } else if (
    url.protocol !== 'file:' &&
    isSpecial(url.protocol) &&
    !host &&
    url.pathname !== '/'
  ) {
    //
    // Add back the empty userinfo, otherwise the original invalid URL
    // might be transformed into a valid one with `url.pathname` as host.
    //
    result += '@';
  }

  //
  // Trailing colon is removed from `url.host` when it is parsed. If it still
  // ends with a colon, then add back the trailing colon that was removed. This
  // prevents an invalid URL from being transformed into a valid one.
  //
  if (host[host.length - 1] === ':' || (port.test(url.hostname) && !url.port)) {
    host += ':';
  }

  result += host + url.pathname;

  query = 'object' === typeof url.query ? stringify(url.query) : url.query;
  if (query) result += '?' !== query.charAt(0) ? '?'+ query : query;

  if (url.hash) result += url.hash;

  return result;
}

Url.prototype = { set: set, toString: toString };

//
// Expose the URL parser and some additional properties that might be useful for
// others or testing.
//
Url.extractProtocol = extractProtocol;
Url.location = lolcation;
Url.trimLeft = trimLeft;
Url.qs = qs;

var urlParse = Url;

var connection = {};

var defs$5 = {};

var codec$2 = {};

var bufferMoreInts = {exports: {}};

bufferMoreInts.exports;

(function (module) {

	// JavaScript is numerically challenged
	var SHIFT_LEFT_32 = (1 << 16) * (1 << 16);
	var SHIFT_RIGHT_32 = 1 / SHIFT_LEFT_32;

	// The maximum contiguous integer that can be held in a IEEE754 double
	var MAX_INT = 0x1fffffffffffff;

	function isContiguousInt(val) {
	    return val <= MAX_INT && val >= -MAX_INT;
	}

	function assertContiguousInt(val) {
	    if (!isContiguousInt(val)) {
	        throw new TypeError("number cannot be represented as a contiguous integer");
	    }
	}

	module.exports.isContiguousInt = isContiguousInt;
	module.exports.assertContiguousInt = assertContiguousInt;

	// Fill in the regular procedures
	['UInt', 'Int'].forEach(function (sign) {
	  var suffix = sign + '8';
	  module.exports['read' + suffix] =
	    Buffer.prototype['read' + suffix].call;
	  module.exports['write' + suffix] =
	    Buffer.prototype['write' + suffix].call;

	  ['16', '32'].forEach(function (size) {
	    ['LE', 'BE'].forEach(function (endian) {
	      var suffix = sign + size + endian;
	      var read = Buffer.prototype['read' + suffix];
	      module.exports['read' + suffix] =
	        function (buf, offset) {
	          return read.call(buf, offset);
	        };
	      var write = Buffer.prototype['write' + suffix];
	      module.exports['write' + suffix] =
	        function (buf, val, offset) {
	          return write.call(buf, val, offset);
	        };
	    });
	  });
	});

	// Check that a value is an integer within the given range
	function check_value(val, min, max) {
	    val = +val;
	    if (typeof(val) != 'number' || val < min || val > max || Math.floor(val) !== val) {
	        throw new TypeError("\"value\" argument is out of bounds");
	    }
	    return val;
	}

	// Check that something is within the Buffer bounds
	function check_bounds(buf, offset, len) {
	    if (offset < 0 || offset + len > buf.length) {
	        throw new RangeError("Index out of range");
	    }
	}

	function readUInt24BE(buf, offset) {
	  return buf.readUInt8(offset) << 16 | buf.readUInt16BE(offset + 1);
	}
	module.exports.readUInt24BE = readUInt24BE;

	function writeUInt24BE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffff);
	    check_bounds(buf, offset, 3);
	    buf.writeUInt8(val >>> 16, offset);
	    buf.writeUInt16BE(val & 0xffff, offset + 1);
	}
	module.exports.writeUInt24BE = writeUInt24BE;

	function readUInt40BE(buf, offset) {
	    return (buf.readUInt8(offset) || 0) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 1);
	}
	module.exports.readUInt40BE = readUInt40BE;

	function writeUInt40BE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffff);
	    check_bounds(buf, offset, 5);
	    buf.writeUInt8(Math.floor(val * SHIFT_RIGHT_32), offset);
	    buf.writeInt32BE(val & -1, offset + 1);
	}
	module.exports.writeUInt40BE = writeUInt40BE;

	function readUInt48BE(buf, offset) {
	    return buf.readUInt16BE(offset) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 2);
	}
	module.exports.readUInt48BE = readUInt48BE;

	function writeUInt48BE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffff);
	    check_bounds(buf, offset, 6);
	    buf.writeUInt16BE(Math.floor(val * SHIFT_RIGHT_32), offset);
	    buf.writeInt32BE(val & -1, offset + 2);
	}
	module.exports.writeUInt48BE = writeUInt48BE;

	function readUInt56BE(buf, offset) {
	    return ((buf.readUInt8(offset) || 0) << 16 | buf.readUInt16BE(offset + 1)) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 3);
	}
	module.exports.readUInt56BE = readUInt56BE;

	function writeUInt56BE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffffff);
	    check_bounds(buf, offset, 7);

	    if (val < 0x100000000000000) {
	        var hi = Math.floor(val * SHIFT_RIGHT_32);
	        buf.writeUInt8(hi >>> 16, offset);
	        buf.writeUInt16BE(hi & 0xffff, offset + 1);
	        buf.writeInt32BE(val & -1, offset + 3);
	    } else {
	        // Special case because 2^56-1 gets rounded up to 2^56
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	    }
	}
	module.exports.writeUInt56BE = writeUInt56BE;

	function readUInt64BE(buf, offset) {
	    return buf.readUInt32BE(offset) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 4);
	}
	module.exports.readUInt64BE = readUInt64BE;

	function writeUInt64BE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffffffff);
	    check_bounds(buf, offset, 8);

	    if (val < 0x10000000000000000) {
	        buf.writeUInt32BE(Math.floor(val * SHIFT_RIGHT_32), offset);
	        buf.writeInt32BE(val & -1, offset + 4);
	    } else {
	        // Special case because 2^64-1 gets rounded up to 2^64
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	        buf[offset+7] = 0xff;
	    }
	}
	module.exports.writeUInt64BE = writeUInt64BE;

	function readUInt24LE(buf, offset) {
	    return buf.readUInt8(offset + 2) << 16 | buf.readUInt16LE(offset);
	}
	module.exports.readUInt24LE = readUInt24LE;

	function writeUInt24LE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffff);
	    check_bounds(buf, offset, 3);

	    buf.writeUInt16LE(val & 0xffff, offset);
	    buf.writeUInt8(val >>> 16, offset + 2);
	}
	module.exports.writeUInt24LE = writeUInt24LE;

	function readUInt40LE(buf, offset) {
	    return (buf.readUInt8(offset + 4) || 0) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readUInt40LE = readUInt40LE;

	function writeUInt40LE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffff);
	    check_bounds(buf, offset, 5);
	    buf.writeInt32LE(val & -1, offset);
	    buf.writeUInt8(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	}
	module.exports.writeUInt40LE = writeUInt40LE;

	function readUInt48LE(buf, offset) {
	    return buf.readUInt16LE(offset + 4) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readUInt48LE = readUInt48LE;

	function writeUInt48LE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffff);
	    check_bounds(buf, offset, 6);
	    buf.writeInt32LE(val & -1, offset);
	    buf.writeUInt16LE(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	}
	module.exports.writeUInt48LE = writeUInt48LE;

	function readUInt56LE(buf, offset) {
	    return ((buf.readUInt8(offset + 6) || 0) << 16 | buf.readUInt16LE(offset + 4)) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readUInt56LE = readUInt56LE;

	function writeUInt56LE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffffff);
	    check_bounds(buf, offset, 7);

	    if (val < 0x100000000000000) {
	        buf.writeInt32LE(val & -1, offset);
	        var hi = Math.floor(val * SHIFT_RIGHT_32);
	        buf.writeUInt16LE(hi & 0xffff, offset + 4);
	        buf.writeUInt8(hi >>> 16, offset + 6);
	    } else {
	        // Special case because 2^56-1 gets rounded up to 2^56
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	    }
	}
	module.exports.writeUInt56LE = writeUInt56LE;

	function readUInt64LE(buf, offset) {
	    return buf.readUInt32LE(offset + 4) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readUInt64LE = readUInt64LE;

	function writeUInt64LE(buf, val, offset) {
	    val = check_value(val, 0, 0xffffffffffffffff);
	    check_bounds(buf, offset, 8);

	    if (val < 0x10000000000000000) {
	        buf.writeInt32LE(val & -1, offset);
	        buf.writeUInt32LE(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	    } else {
	        // Special case because 2^64-1 gets rounded up to 2^64
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	        buf[offset+7] = 0xff;
	    }
	}
	module.exports.writeUInt64LE = writeUInt64LE;


	function readInt24BE(buf, offset) {
	    return (buf.readInt8(offset) << 16) + buf.readUInt16BE(offset + 1);
	}
	module.exports.readInt24BE = readInt24BE;

	function writeInt24BE(buf, val, offset) {
	    val = check_value(val, -0x800000, 0x7fffff);
	    check_bounds(buf, offset, 3);
	    buf.writeInt8(val >> 16, offset);
	    buf.writeUInt16BE(val & 0xffff, offset + 1);
	}
	module.exports.writeInt24BE = writeInt24BE;

	function readInt40BE(buf, offset) {
	    return (buf.readInt8(offset) || 0) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 1);
	}
	module.exports.readInt40BE = readInt40BE;

	function writeInt40BE(buf, val, offset) {
	    val = check_value(val, -0x8000000000, 0x7fffffffff);
	    check_bounds(buf, offset, 5);
	    buf.writeInt8(Math.floor(val * SHIFT_RIGHT_32), offset);
	    buf.writeInt32BE(val & -1, offset + 1);
	}
	module.exports.writeInt40BE = writeInt40BE;

	function readInt48BE(buf, offset) {
	    return buf.readInt16BE(offset) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 2);
	}
	module.exports.readInt48BE = readInt48BE;

	function writeInt48BE(buf, val, offset) {
	    val = check_value(val, -0x800000000000, 0x7fffffffffff);
	    check_bounds(buf, offset, 6);
	    buf.writeInt16BE(Math.floor(val * SHIFT_RIGHT_32), offset);
	    buf.writeInt32BE(val & -1, offset + 2);
	}
	module.exports.writeInt48BE = writeInt48BE;

	function readInt56BE(buf, offset) {
	    return (((buf.readInt8(offset) || 0) << 16) + buf.readUInt16BE(offset + 1)) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 3);
	}
	module.exports.readInt56BE = readInt56BE;

	function writeInt56BE(buf, val, offset) {
	    val = check_value(val, -0x800000000000000, 0x7fffffffffffff);
	    check_bounds(buf, offset, 7);

	    if (val < 0x80000000000000) {
	        var hi = Math.floor(val * SHIFT_RIGHT_32);
	        buf.writeInt8(hi >> 16, offset);
	        buf.writeUInt16BE(hi & 0xffff, offset + 1);
	        buf.writeInt32BE(val & -1, offset + 3);
	    } else {
	        // Special case because 2^55-1 gets rounded up to 2^55
	        buf[offset] = 0x7f;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	    }
	}
	module.exports.writeInt56BE = writeInt56BE;

	function readInt64BE(buf, offset) {
	    return buf.readInt32BE(offset) * SHIFT_LEFT_32 + buf.readUInt32BE(offset + 4);
	}
	module.exports.readInt64BE = readInt64BE;

	function writeInt64BE(buf, val, offset) {
	    val = check_value(val, -0x800000000000000000, 0x7fffffffffffffff);
	    check_bounds(buf, offset, 8);

	    if (val < 0x8000000000000000) {
	        buf.writeInt32BE(Math.floor(val * SHIFT_RIGHT_32), offset);
	        buf.writeInt32BE(val & -1, offset + 4);
	    } else {
	        // Special case because 2^63-1 gets rounded up to 2^63
	        buf[offset] = 0x7f;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	        buf[offset+7] = 0xff;
	    }
	}
	module.exports.writeInt64BE = writeInt64BE;

	function readInt24LE(buf, offset) {
	    return (buf.readInt8(offset + 2) << 16) + buf.readUInt16LE(offset);
	}
	module.exports.readInt24LE = readInt24LE;

	function writeInt24LE(buf, val, offset) {
	    val = check_value(val, -0x800000, 0x7fffff);
	    check_bounds(buf, offset, 3);
	    buf.writeUInt16LE(val & 0xffff, offset);
	    buf.writeInt8(val >> 16, offset + 2);
	}
	module.exports.writeInt24LE = writeInt24LE;

	function readInt40LE(buf, offset) {
	    return (buf.readInt8(offset + 4) || 0) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readInt40LE = readInt40LE;

	function writeInt40LE(buf, val, offset) {
	    val = check_value(val, -0x8000000000, 0x7fffffffff);
	    check_bounds(buf, offset, 5);
	    buf.writeInt32LE(val & -1, offset);
	    buf.writeInt8(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	}
	module.exports.writeInt40LE = writeInt40LE;

	function readInt48LE(buf, offset) {
	    return buf.readInt16LE(offset + 4) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readInt48LE = readInt48LE;

	function writeInt48LE(buf, val, offset) {
	    val = check_value(val, -0x800000000000, 0x7fffffffffff);
	    check_bounds(buf, offset, 6);
	    buf.writeInt32LE(val & -1, offset);
	    buf.writeInt16LE(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	}
	module.exports.writeInt48LE = writeInt48LE;

	function readInt56LE(buf, offset) {
	    return (((buf.readInt8(offset + 6) || 0) << 16) + buf.readUInt16LE(offset + 4)) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readInt56LE = readInt56LE;

	function writeInt56LE(buf, val, offset) {
	    val = check_value(val, -0x80000000000000, 0x7fffffffffffff);
	    check_bounds(buf, offset, 7);

	    if (val < 0x80000000000000) {
	        buf.writeInt32LE(val & -1, offset);
	        var hi = Math.floor(val * SHIFT_RIGHT_32);
	        buf.writeUInt16LE(hi & 0xffff, offset + 4);
	        buf.writeInt8(hi >> 16, offset + 6);
	    } else {
	        // Special case because 2^55-1 gets rounded up to 2^55
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0x7f;
	    }
	}
	module.exports.writeInt56LE = writeInt56LE;

	function readInt64LE(buf, offset) {
	    return buf.readInt32LE(offset + 4) * SHIFT_LEFT_32 + buf.readUInt32LE(offset);
	}
	module.exports.readInt64LE = readInt64LE;

	function writeInt64LE(buf, val, offset) {
	    val = check_value(val, -0x8000000000000000, 0x7fffffffffffffff);
	    check_bounds(buf, offset, 8);

	    if (val < 0x8000000000000000) {
	        buf.writeInt32LE(val & -1, offset);
	        buf.writeInt32LE(Math.floor(val * SHIFT_RIGHT_32), offset + 4);
	    } else {
	        // Special case because 2^55-1 gets rounded up to 2^55
	        buf[offset] = 0xff;
	        buf[offset+1] = 0xff;
	        buf[offset+2] = 0xff;
	        buf[offset+3] = 0xff;
	        buf[offset+4] = 0xff;
	        buf[offset+5] = 0xff;
	        buf[offset+6] = 0xff;
	        buf[offset+7] = 0x7f;
	    }
	}
	module.exports.writeInt64LE = writeInt64LE; 
} (bufferMoreInts));

var bufferMoreIntsExports = bufferMoreInts.exports;

var ints$2 = bufferMoreIntsExports;

// JavaScript uses only doubles so what I'm testing for is whether
// it's *better* to encode a number as a float or double. This really
// just amounts to testing whether there's a fractional part to the
// number, except that see below. NB I don't use bitwise operations to
// do this 'efficiently' -- it would mask the number to 32 bits.
//
// At 2^50, doubles don't have sufficient precision to distinguish
// between floating point and integer numbers (`Math.pow(2, 50) + 0.1
// === Math.pow(2, 50)` (and, above 2^53, doubles cannot represent all
// integers (`Math.pow(2, 53) + 1 === Math.pow(2, 53)`)). Hence
// anything with a magnitude at or above 2^50 may as well be encoded
// as a 64-bit integer. Except that only signed integers are supported
// by RabbitMQ, so anything above 2^63 - 1 must be a double.
function isFloatingPoint(n) {
    return n >= 0x8000000000000000 ||
        (Math.abs(n) < 0x4000000000000
         && Math.floor(n) !== n);
}

function encodeTable$1(buffer, val, offset) {
    var start = offset;
    offset += 4; // leave room for the table length
    for (var key in val) {
        if (val[key] !== undefined) {
          var len = Buffer.byteLength(key);
          buffer.writeUInt8(len, offset); offset++;
          buffer.write(key, offset, 'utf8'); offset += len;
          offset += encodeFieldValue(buffer, val[key], offset);
        }
    }
    var size = offset - start;
    buffer.writeUInt32BE(size - 4, start);
    return size;
}

function encodeArray(buffer, val, offset) {
    var start = offset;
    offset += 4;
    for (var i=0, num=val.length; i < num; i++) {
        offset += encodeFieldValue(buffer, val[i], offset);
    }
    var size = offset - start;
    buffer.writeUInt32BE(size - 4, start);
    return size;
}

function encodeFieldValue(buffer, value, offset) {
    var start = offset;
    var type = typeof value, val = value;
    // A trapdoor for specifying a type, e.g., timestamp
    if (value && type === 'object' && value.hasOwnProperty('!')) {
        val = value.value;
        type = value['!'];
    }

    // If it's a JS number, we'll have to guess what type to encode it
    // as.
    if (type == 'number') {
        // Making assumptions about the kind of number (floating point
        // v integer, signed, unsigned, size) desired is dangerous in
        // general; however, in practice RabbitMQ uses only
        // longstrings and unsigned integers in its arguments, and
        // other clients generally conflate number types anyway. So
        // the only distinction we care about is floating point vs
        // integers, preferring integers since those can be promoted
        // if necessary. If floating point is required, we may as well
        // use double precision.
        if (isFloatingPoint(val)) {
            type = 'double';
        }
        else { // only signed values are used in tables by
               // RabbitMQ. It *used* to (< v3.3.0) treat the byte 'b'
               // type as unsigned, but most clients (and the spec)
               // think it's signed, and now RabbitMQ does too.
            if (val < 128 && val >= -128) {
                type = 'byte';
            }
            else if (val >= -0x8000 && val < 0x8000) {
                type = 'short';
            }
            else if (val >= -0x80000000 && val < 0x80000000) {
                type = 'int';
            }
            else {
                type = 'long';
            }
        }
    }

    function tag(t) { buffer.write(t, offset); offset++; }

    switch (type) {
    case 'string': // no shortstr in field tables
        var len = Buffer.byteLength(val, 'utf8');
        tag('S');
        buffer.writeUInt32BE(len, offset); offset += 4;
        buffer.write(val, offset, 'utf8'); offset += len;
        break;
    case 'object':
        if (val === null) {
            tag('V');
        }
        else if (Array.isArray(val)) {
            tag('A');
            offset += encodeArray(buffer, val, offset);
        }
        else if (Buffer.isBuffer(val)) {
            tag('x');
            buffer.writeUInt32BE(val.length, offset); offset += 4;
            val.copy(buffer, offset); offset += val.length;
        }
        else {
            tag('F');
            offset += encodeTable$1(buffer, val, offset);
        }
        break;
    case 'boolean':
        tag('t');
        buffer.writeUInt8((val) ? 1 : 0, offset); offset++;
        break;
    // These are the types that are either guessed above, or
    // explicitly given using the {'!': type} notation.
    case 'double':
    case 'float64':
        tag('d');
        buffer.writeDoubleBE(val, offset);
        offset += 8;
        break;
    case 'byte':
    case 'int8':
        tag('b');
        buffer.writeInt8(val, offset); offset++;
        break;
    case 'unsignedbyte':
    case 'uint8':
        tag('B');
        buffer.writeUInt8(val, offset); offset++;
        break;
    case 'short':
    case 'int16':
        tag('s');
        buffer.writeInt16BE(val, offset); offset += 2;
        break;
    case 'unsignedshort':
    case 'uint16':
        tag('u');
        buffer.writeUInt16BE(val, offset); offset += 2;
        break;
    case 'int':
    case 'int32':
        tag('I');
        buffer.writeInt32BE(val, offset); offset += 4;
        break;
    case 'unsignedint':
    case 'uint32':
        tag('i');
        buffer.writeUInt32BE(val, offset); offset += 4;
        break;
    case 'long':
    case 'int64':
        tag('l');
        ints$2.writeInt64BE(buffer, val, offset); offset += 8;
        break;

    // Now for exotic types, those can _only_ be denoted by using
    // `{'!': type, value: val}
    case 'timestamp':
        tag('T');
        ints$2.writeUInt64BE(buffer, val, offset); offset += 8;
        break;
    case 'float':
        tag('f');
        buffer.writeFloatBE(val, offset); offset += 4;
        break;
    case 'decimal':
        tag('D');
        if (val.hasOwnProperty('places') && val.hasOwnProperty('digits')
            && val.places >= 0 && val.places < 256) {
            buffer[offset] = val.places; offset++;
            buffer.writeUInt32BE(val.digits, offset); offset += 4;
        }
        else throw new TypeError(
            "Decimal value must be {'places': 0..255, 'digits': uint32}, " +
                "got " + JSON.stringify(val));
        break;
    default:
        throw new TypeError('Unknown type to encode: ' + type);
    }
    return offset - start;
}

// Assume we're given a slice of the buffer that contains just the
// fields.
function decodeFields$1(slice) {
    var fields = {}, offset = 0, size = slice.length;
    var len, key, val;

    function decodeFieldValue() {
        var tag = String.fromCharCode(slice[offset]); offset++;
        switch (tag) {
        case 'b':
            val = slice.readInt8(offset); offset++;
            break;
        case 'B':
            val = slice.readUInt8(offset); offset++;
            break;
        case 'S':
            len = slice.readUInt32BE(offset); offset += 4;
            val = slice.toString('utf8', offset, offset + len);
            offset += len;
            break;
        case 'I':
            val = slice.readInt32BE(offset); offset += 4;
            break;
        case 'i':
            val = slice.readUInt32BE(offset); offset += 4;
            break;
        case 'D': // only positive decimals, apparently.
            var places = slice[offset]; offset++;
            var digits = slice.readUInt32BE(offset); offset += 4;
            val = {'!': 'decimal', value: {places: places, digits: digits}};
            break;
        case 'T':
            val = ints$2.readUInt64BE(slice, offset); offset += 8;
            val = {'!': 'timestamp', value: val};
            break;
        case 'F':
            len = slice.readUInt32BE(offset); offset += 4;
            val = decodeFields$1(slice.subarray(offset, offset + len));
            offset += len;
            break;
        case 'A':
            len = slice.readUInt32BE(offset); offset += 4;
            decodeArray(offset + len);
            // NB decodeArray will itself update offset and val
            break;
        case 'd':
            val = slice.readDoubleBE(offset); offset += 8;
            break;
        case 'f':
            val = slice.readFloatBE(offset); offset += 4;
            break;
        case 'l':
            val = ints$2.readInt64BE(slice, offset); offset += 8;
            break;
        case 's':
            val = slice.readInt16BE(offset); offset += 2;
            break;
        case 'u':
            val = slice.readUInt16BE(offset); offset += 2;
            break;
        case 't':
            val = slice[offset] != 0; offset++;
            break;
        case 'V':
            val = null;
            break;
        case 'x':
            len = slice.readUInt32BE(offset); offset += 4;
            val = slice.subarray(offset, offset + len);
            offset += len;
            break;
        default:
            throw new TypeError('Unexpected type tag "' + tag +'"');
        }
    }

    function decodeArray(until) {
        var vals = [];
        while (offset < until) {
            decodeFieldValue();
            vals.push(val);
        }
        val = vals;
    }

    while (offset < size) {
        len = slice.readUInt8(offset); offset++;
        key = slice.toString('utf8', offset, offset + len);
        offset += len;
        decodeFieldValue();
        fields[key] = val;
    }
    return fields;
}

codec$2.encodeTable = encodeTable$1;
codec$2.decodeFields = decodeFields$1;

/** @preserve This file is generated by the script
 * ../bin/generate-defs.js, which is not in general included in a
 * distribution, but is available in the source repository e.g. at
 * https://github.com/squaremo/amqp.node/
 */

function decodeBasicQos(buffer) {
  var val, offset = 0, fields = {
    prefetchSize: void 0,
    prefetchCount: void 0,
    global: void 0
  };
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.prefetchSize = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.prefetchCount = val;
  val = !!(1 & buffer[offset]);
  fields.global = val;
  return fields;
}

function encodeBasicQos(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(19);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932170, 7);
  offset = 11;
  val = fields.prefetchSize;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'prefetchSize' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  val = fields.prefetchCount;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'prefetchCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.global;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicQosOk(buffer) {
  return {};
}

function encodeBasicQosOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932171, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicConsume(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    consumerTag: void 0,
    noLocal: void 0,
    noAck: void 0,
    exclusive: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.consumerTag = val;
  val = !!(1 & buffer[offset]);
  fields.noLocal = val;
  val = !!(2 & buffer[offset]);
  fields.noAck = val;
  val = !!(4 & buffer[offset]);
  fields.exclusive = val;
  val = !!(8 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeBasicConsume(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  val = fields.consumerTag;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'consumerTag' is the wrong type; must be a string (up to 255 chars)");
  var consumerTag_len = Buffer.byteLength(val, "utf8");
  varyingSize += consumerTag_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932180, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.consumerTag;
  void 0 === val && (val = "");
  buffer[offset] = consumerTag_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += consumerTag_len;
  val = fields.noLocal;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.noAck;
  void 0 === val && (val = !1);
  val && (bits += 2);
  val = fields.exclusive;
  void 0 === val && (val = !1);
  val && (bits += 4);
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 8);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicConsumeOk(buffer) {
  var val, len, offset = 0, fields = {
    consumerTag: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.consumerTag = val;
  return fields;
}

function encodeBasicConsumeOk(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.consumerTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'consumerTag'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'consumerTag' is the wrong type; must be a string (up to 255 chars)");
  var consumerTag_len = Buffer.byteLength(val, "utf8");
  varyingSize += consumerTag_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932181, 7);
  offset = 11;
  val = fields.consumerTag;
  void 0 === val && (val = void 0);
  buffer[offset] = consumerTag_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += consumerTag_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicCancel(buffer) {
  var val, len, offset = 0, fields = {
    consumerTag: void 0,
    nowait: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.consumerTag = val;
  val = !!(1 & buffer[offset]);
  fields.nowait = val;
  return fields;
}

function encodeBasicCancel(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.consumerTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'consumerTag'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'consumerTag' is the wrong type; must be a string (up to 255 chars)");
  var consumerTag_len = Buffer.byteLength(val, "utf8");
  varyingSize += consumerTag_len;
  var buffer = Buffer.alloc(14 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932190, 7);
  offset = 11;
  val = fields.consumerTag;
  void 0 === val && (val = void 0);
  buffer[offset] = consumerTag_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += consumerTag_len;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicCancelOk(buffer) {
  var val, len, offset = 0, fields = {
    consumerTag: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.consumerTag = val;
  return fields;
}

function encodeBasicCancelOk(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.consumerTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'consumerTag'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'consumerTag' is the wrong type; must be a string (up to 255 chars)");
  var consumerTag_len = Buffer.byteLength(val, "utf8");
  varyingSize += consumerTag_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932191, 7);
  offset = 11;
  val = fields.consumerTag;
  void 0 === val && (val = void 0);
  buffer[offset] = consumerTag_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += consumerTag_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicPublish(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    exchange: void 0,
    routingKey: void 0,
    mandatory: void 0,
    immediate: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  val = !!(1 & buffer[offset]);
  fields.mandatory = val;
  val = !!(2 & buffer[offset]);
  fields.immediate = val;
  return fields;
}

function encodeBasicPublish(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.exchange;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932200, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.exchange;
  void 0 === val && (val = "");
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = "");
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  val = fields.mandatory;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.immediate;
  void 0 === val && (val = !1);
  val && (bits += 2);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicReturn(buffer) {
  var val, len, offset = 0, fields = {
    replyCode: void 0,
    replyText: void 0,
    exchange: void 0,
    routingKey: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.replyCode = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.replyText = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  return fields;
}

function encodeBasicReturn(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.replyText;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'replyText' is the wrong type; must be a string (up to 255 chars)");
  var replyText_len = Buffer.byteLength(val, "utf8");
  varyingSize += replyText_len;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'routingKey'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932210, 7);
  offset = 11;
  val = fields.replyCode;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'replyCode'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'replyCode' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.replyText;
  void 0 === val && (val = "");
  buffer[offset] = replyText_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += replyText_len;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = void 0);
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicDeliver(buffer) {
  var val, len, offset = 0, fields = {
    consumerTag: void 0,
    deliveryTag: void 0,
    redelivered: void 0,
    exchange: void 0,
    routingKey: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.consumerTag = val;
  val = ints$1.readUInt64BE(buffer, offset);
  offset += 8;
  fields.deliveryTag = val;
  val = !!(1 & buffer[offset]);
  fields.redelivered = val;
  offset++;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  return fields;
}

function encodeBasicDeliver(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.consumerTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'consumerTag'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'consumerTag' is the wrong type; must be a string (up to 255 chars)");
  var consumerTag_len = Buffer.byteLength(val, "utf8");
  varyingSize += consumerTag_len;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'routingKey'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  var buffer = Buffer.alloc(24 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932220, 7);
  offset = 11;
  val = fields.consumerTag;
  void 0 === val && (val = void 0);
  buffer[offset] = consumerTag_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += consumerTag_len;
  val = fields.deliveryTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'deliveryTag'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryTag' is the wrong type; must be a number (but not NaN)");
  ints$1.writeUInt64BE(buffer, val, offset);
  offset += 8;
  val = fields.redelivered;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = void 0);
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicGet(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    noAck: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  val = !!(1 & buffer[offset]);
  fields.noAck = val;
  return fields;
}

function encodeBasicGet(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932230, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.noAck;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicGetOk(buffer) {
  var val, len, offset = 0, fields = {
    deliveryTag: void 0,
    redelivered: void 0,
    exchange: void 0,
    routingKey: void 0,
    messageCount: void 0
  };
  val = ints$1.readUInt64BE(buffer, offset);
  offset += 8;
  fields.deliveryTag = val;
  val = !!(1 & buffer[offset]);
  fields.redelivered = val;
  offset++;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.messageCount = val;
  return fields;
}

function encodeBasicGetOk(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'routingKey'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  var buffer = Buffer.alloc(27 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932231, 7);
  offset = 11;
  val = fields.deliveryTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'deliveryTag'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryTag' is the wrong type; must be a number (but not NaN)");
  ints$1.writeUInt64BE(buffer, val, offset);
  offset += 8;
  val = fields.redelivered;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = void 0);
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  val = fields.messageCount;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'messageCount'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'messageCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicGetEmpty(buffer) {
  var val, len, offset = 0, fields = {
    clusterId: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.clusterId = val;
  return fields;
}

function encodeBasicGetEmpty(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.clusterId;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'clusterId' is the wrong type; must be a string (up to 255 chars)");
  var clusterId_len = Buffer.byteLength(val, "utf8");
  varyingSize += clusterId_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932232, 7);
  offset = 11;
  val = fields.clusterId;
  void 0 === val && (val = "");
  buffer[offset] = clusterId_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += clusterId_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicAck(buffer) {
  var val, offset = 0, fields = {
    deliveryTag: void 0,
    multiple: void 0
  };
  val = ints$1.readUInt64BE(buffer, offset);
  offset += 8;
  fields.deliveryTag = val;
  val = !!(1 & buffer[offset]);
  fields.multiple = val;
  return fields;
}

function encodeBasicAck(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(21);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932240, 7);
  offset = 11;
  val = fields.deliveryTag;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryTag' is the wrong type; must be a number (but not NaN)");
  ints$1.writeUInt64BE(buffer, val, offset);
  offset += 8;
  val = fields.multiple;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicReject(buffer) {
  var val, offset = 0, fields = {
    deliveryTag: void 0,
    requeue: void 0
  };
  val = ints$1.readUInt64BE(buffer, offset);
  offset += 8;
  fields.deliveryTag = val;
  val = !!(1 & buffer[offset]);
  fields.requeue = val;
  return fields;
}

function encodeBasicReject(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(21);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932250, 7);
  offset = 11;
  val = fields.deliveryTag;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'deliveryTag'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryTag' is the wrong type; must be a number (but not NaN)");
  ints$1.writeUInt64BE(buffer, val, offset);
  offset += 8;
  val = fields.requeue;
  void 0 === val && (val = !0);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicRecoverAsync(buffer) {
  var val, fields = {
    requeue: void 0
  };
  val = !!(1 & buffer[0]);
  fields.requeue = val;
  return fields;
}

function encodeBasicRecoverAsync(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(13);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932260, 7);
  offset = 11;
  val = fields.requeue;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicRecover(buffer) {
  var val, fields = {
    requeue: void 0
  };
  val = !!(1 & buffer[0]);
  fields.requeue = val;
  return fields;
}

function encodeBasicRecover(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(13);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932270, 7);
  offset = 11;
  val = fields.requeue;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicRecoverOk(buffer) {
  return {};
}

function encodeBasicRecoverOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932271, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeBasicNack(buffer) {
  var val, offset = 0, fields = {
    deliveryTag: void 0,
    multiple: void 0,
    requeue: void 0
  };
  val = ints$1.readUInt64BE(buffer, offset);
  offset += 8;
  fields.deliveryTag = val;
  val = !!(1 & buffer[offset]);
  fields.multiple = val;
  val = !!(2 & buffer[offset]);
  fields.requeue = val;
  return fields;
}

function encodeBasicNack(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(21);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932280, 7);
  offset = 11;
  val = fields.deliveryTag;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryTag' is the wrong type; must be a number (but not NaN)");
  ints$1.writeUInt64BE(buffer, val, offset);
  offset += 8;
  val = fields.multiple;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.requeue;
  void 0 === val && (val = !0);
  val && (bits += 2);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionStart(buffer) {
  var val, len, offset = 0, fields = {
    versionMajor: void 0,
    versionMinor: void 0,
    serverProperties: void 0,
    mechanisms: void 0,
    locales: void 0
  };
  val = buffer[offset];
  offset++;
  fields.versionMajor = val;
  val = buffer[offset];
  offset++;
  fields.versionMinor = val;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.serverProperties = val;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.mechanisms = val;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.locales = val;
  return fields;
}

function encodeConnectionStart(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0, scratchOffset = 0;
  val = fields.serverProperties;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'serverProperties'");
  if ("object" != typeof val) throw new TypeError("Field 'serverProperties' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var serverProperties_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += serverProperties_encoded.length;
  val = fields.mechanisms;
  if (void 0 === val) val = Buffer.from("PLAIN"); else if (!Buffer.isBuffer(val)) throw new TypeError("Field 'mechanisms' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  val = fields.locales;
  if (void 0 === val) val = Buffer.from("en_US"); else if (!Buffer.isBuffer(val)) throw new TypeError("Field 'locales' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  var buffer = Buffer.alloc(22 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655370, 7);
  offset = 11;
  val = fields.versionMajor;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'versionMajor' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt8(val, offset);
  offset++;
  val = fields.versionMinor;
  if (void 0 === val) val = 9; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'versionMinor' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt8(val, offset);
  offset++;
  offset += serverProperties_encoded.copy(buffer, offset);
  val = fields.mechanisms;
  void 0 === val && (val = Buffer.from("PLAIN"));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  val = fields.locales;
  void 0 === val && (val = Buffer.from("en_US"));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionStartOk(buffer) {
  var val, len, offset = 0, fields = {
    clientProperties: void 0,
    mechanism: void 0,
    response: void 0,
    locale: void 0
  };
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.clientProperties = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.mechanism = val;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.response = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.locale = val;
  return fields;
}

function encodeConnectionStartOk(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0, scratchOffset = 0;
  val = fields.clientProperties;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'clientProperties'");
  if ("object" != typeof val) throw new TypeError("Field 'clientProperties' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var clientProperties_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += clientProperties_encoded.length;
  val = fields.mechanism;
  if (void 0 === val) val = "PLAIN"; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'mechanism' is the wrong type; must be a string (up to 255 chars)");
  var mechanism_len = Buffer.byteLength(val, "utf8");
  varyingSize += mechanism_len;
  val = fields.response;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'response'");
  if (!Buffer.isBuffer(val)) throw new TypeError("Field 'response' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  val = fields.locale;
  if (void 0 === val) val = "en_US"; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'locale' is the wrong type; must be a string (up to 255 chars)");
  var locale_len = Buffer.byteLength(val, "utf8");
  varyingSize += locale_len;
  var buffer = Buffer.alloc(18 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655371, 7);
  offset = 11;
  offset += clientProperties_encoded.copy(buffer, offset);
  val = fields.mechanism;
  void 0 === val && (val = "PLAIN");
  buffer[offset] = mechanism_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += mechanism_len;
  val = fields.response;
  void 0 === val && (val = Buffer.from(void 0));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  val = fields.locale;
  void 0 === val && (val = "en_US");
  buffer[offset] = locale_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += locale_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionSecure(buffer) {
  var val, len, offset = 0, fields = {
    challenge: void 0
  };
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.challenge = val;
  return fields;
}

function encodeConnectionSecure(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0;
  val = fields.challenge;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'challenge'");
  if (!Buffer.isBuffer(val)) throw new TypeError("Field 'challenge' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655380, 7);
  offset = 11;
  val = fields.challenge;
  void 0 === val && (val = Buffer.from(void 0));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionSecureOk(buffer) {
  var val, len, offset = 0, fields = {
    response: void 0
  };
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.response = val;
  return fields;
}

function encodeConnectionSecureOk(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0;
  val = fields.response;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'response'");
  if (!Buffer.isBuffer(val)) throw new TypeError("Field 'response' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655381, 7);
  offset = 11;
  val = fields.response;
  void 0 === val && (val = Buffer.from(void 0));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionTune(buffer) {
  var val, offset = 0, fields = {
    channelMax: void 0,
    frameMax: void 0,
    heartbeat: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.channelMax = val;
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.frameMax = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.heartbeat = val;
  return fields;
}

function encodeConnectionTune(channel, fields) {
  var offset = 0, val = null, buffer = Buffer.alloc(20);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655390, 7);
  offset = 11;
  val = fields.channelMax;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'channelMax' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.frameMax;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'frameMax' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  val = fields.heartbeat;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'heartbeat' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionTuneOk(buffer) {
  var val, offset = 0, fields = {
    channelMax: void 0,
    frameMax: void 0,
    heartbeat: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.channelMax = val;
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.frameMax = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.heartbeat = val;
  return fields;
}

function encodeConnectionTuneOk(channel, fields) {
  var offset = 0, val = null, buffer = Buffer.alloc(20);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655391, 7);
  offset = 11;
  val = fields.channelMax;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'channelMax' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.frameMax;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'frameMax' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  val = fields.heartbeat;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'heartbeat' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionOpen(buffer) {
  var val, len, offset = 0, fields = {
    virtualHost: void 0,
    capabilities: void 0,
    insist: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.virtualHost = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.capabilities = val;
  val = !!(1 & buffer[offset]);
  fields.insist = val;
  return fields;
}

function encodeConnectionOpen(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.virtualHost;
  if (void 0 === val) val = "/"; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'virtualHost' is the wrong type; must be a string (up to 255 chars)");
  var virtualHost_len = Buffer.byteLength(val, "utf8");
  varyingSize += virtualHost_len;
  val = fields.capabilities;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'capabilities' is the wrong type; must be a string (up to 255 chars)");
  var capabilities_len = Buffer.byteLength(val, "utf8");
  varyingSize += capabilities_len;
  var buffer = Buffer.alloc(15 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655400, 7);
  offset = 11;
  val = fields.virtualHost;
  void 0 === val && (val = "/");
  buffer[offset] = virtualHost_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += virtualHost_len;
  val = fields.capabilities;
  void 0 === val && (val = "");
  buffer[offset] = capabilities_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += capabilities_len;
  val = fields.insist;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionOpenOk(buffer) {
  var val, len, offset = 0, fields = {
    knownHosts: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.knownHosts = val;
  return fields;
}

function encodeConnectionOpenOk(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.knownHosts;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'knownHosts' is the wrong type; must be a string (up to 255 chars)");
  var knownHosts_len = Buffer.byteLength(val, "utf8");
  varyingSize += knownHosts_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655401, 7);
  offset = 11;
  val = fields.knownHosts;
  void 0 === val && (val = "");
  buffer[offset] = knownHosts_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += knownHosts_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionClose(buffer) {
  var val, len, offset = 0, fields = {
    replyCode: void 0,
    replyText: void 0,
    classId: void 0,
    methodId: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.replyCode = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.replyText = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.classId = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.methodId = val;
  return fields;
}

function encodeConnectionClose(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.replyText;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'replyText' is the wrong type; must be a string (up to 255 chars)");
  var replyText_len = Buffer.byteLength(val, "utf8");
  varyingSize += replyText_len;
  var buffer = Buffer.alloc(19 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655410, 7);
  offset = 11;
  val = fields.replyCode;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'replyCode'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'replyCode' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.replyText;
  void 0 === val && (val = "");
  buffer[offset] = replyText_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += replyText_len;
  val = fields.classId;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'classId'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'classId' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.methodId;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'methodId'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'methodId' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionCloseOk(buffer) {
  return {};
}

function encodeConnectionCloseOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655411, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionBlocked(buffer) {
  var val, len, offset = 0, fields = {
    reason: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.reason = val;
  return fields;
}

function encodeConnectionBlocked(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.reason;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'reason' is the wrong type; must be a string (up to 255 chars)");
  var reason_len = Buffer.byteLength(val, "utf8");
  varyingSize += reason_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655420, 7);
  offset = 11;
  val = fields.reason;
  void 0 === val && (val = "");
  buffer[offset] = reason_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += reason_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionUnblocked(buffer) {
  return {};
}

function encodeConnectionUnblocked(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655421, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionUpdateSecret(buffer) {
  var val, len, offset = 0, fields = {
    newSecret: void 0,
    reason: void 0
  };
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.newSecret = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.reason = val;
  return fields;
}

function encodeConnectionUpdateSecret(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0;
  val = fields.newSecret;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'newSecret'");
  if (!Buffer.isBuffer(val)) throw new TypeError("Field 'newSecret' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  val = fields.reason;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'reason'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'reason' is the wrong type; must be a string (up to 255 chars)");
  var reason_len = Buffer.byteLength(val, "utf8");
  varyingSize += reason_len;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655430, 7);
  offset = 11;
  val = fields.newSecret;
  void 0 === val && (val = Buffer.from(void 0));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  val = fields.reason;
  void 0 === val && (val = void 0);
  buffer[offset] = reason_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += reason_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConnectionUpdateSecretOk(buffer) {
  return {};
}

function encodeConnectionUpdateSecretOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(655431, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelOpen(buffer) {
  var val, len, offset = 0, fields = {
    outOfBand: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.outOfBand = val;
  return fields;
}

function encodeChannelOpen(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.outOfBand;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'outOfBand' is the wrong type; must be a string (up to 255 chars)");
  var outOfBand_len = Buffer.byteLength(val, "utf8");
  varyingSize += outOfBand_len;
  var buffer = Buffer.alloc(13 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310730, 7);
  offset = 11;
  val = fields.outOfBand;
  void 0 === val && (val = "");
  buffer[offset] = outOfBand_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += outOfBand_len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelOpenOk(buffer) {
  var val, len, offset = 0, fields = {
    channelId: void 0
  };
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = buffer.subarray(offset, offset + len);
  offset += len;
  fields.channelId = val;
  return fields;
}

function encodeChannelOpenOk(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0;
  val = fields.channelId;
  if (void 0 === val) val = Buffer.from(""); else if (!Buffer.isBuffer(val)) throw new TypeError("Field 'channelId' is the wrong type; must be a Buffer");
  varyingSize += val.length;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310731, 7);
  offset = 11;
  val = fields.channelId;
  void 0 === val && (val = Buffer.from(""));
  len = val.length;
  buffer.writeUInt32BE(len, offset);
  offset += 4;
  val.copy(buffer, offset);
  offset += len;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelFlow(buffer) {
  var val, fields = {
    active: void 0
  };
  val = !!(1 & buffer[0]);
  fields.active = val;
  return fields;
}

function encodeChannelFlow(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(13);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310740, 7);
  offset = 11;
  val = fields.active;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'active'");
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelFlowOk(buffer) {
  var val, fields = {
    active: void 0
  };
  val = !!(1 & buffer[0]);
  fields.active = val;
  return fields;
}

function encodeChannelFlowOk(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(13);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310741, 7);
  offset = 11;
  val = fields.active;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'active'");
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelClose(buffer) {
  var val, len, offset = 0, fields = {
    replyCode: void 0,
    replyText: void 0,
    classId: void 0,
    methodId: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.replyCode = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.replyText = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.classId = val;
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.methodId = val;
  return fields;
}

function encodeChannelClose(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.replyText;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'replyText' is the wrong type; must be a string (up to 255 chars)");
  var replyText_len = Buffer.byteLength(val, "utf8");
  varyingSize += replyText_len;
  var buffer = Buffer.alloc(19 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310760, 7);
  offset = 11;
  val = fields.replyCode;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'replyCode'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'replyCode' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.replyText;
  void 0 === val && (val = "");
  buffer[offset] = replyText_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += replyText_len;
  val = fields.classId;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'classId'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'classId' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.methodId;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'methodId'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'methodId' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeChannelCloseOk(buffer) {
  return {};
}

function encodeChannelCloseOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1310761, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeAccessRequest(buffer) {
  var val, len, offset = 0, fields = {
    realm: void 0,
    exclusive: void 0,
    passive: void 0,
    active: void 0,
    write: void 0,
    read: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.realm = val;
  val = !!(1 & buffer[offset]);
  fields.exclusive = val;
  val = !!(2 & buffer[offset]);
  fields.passive = val;
  val = !!(4 & buffer[offset]);
  fields.active = val;
  val = !!(8 & buffer[offset]);
  fields.write = val;
  val = !!(16 & buffer[offset]);
  fields.read = val;
  return fields;
}

function encodeAccessRequest(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.realm;
  if (void 0 === val) val = "/data"; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'realm' is the wrong type; must be a string (up to 255 chars)");
  var realm_len = Buffer.byteLength(val, "utf8");
  varyingSize += realm_len;
  var buffer = Buffer.alloc(14 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1966090, 7);
  offset = 11;
  val = fields.realm;
  void 0 === val && (val = "/data");
  buffer[offset] = realm_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += realm_len;
  val = fields.exclusive;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.passive;
  void 0 === val && (val = !0);
  val && (bits += 2);
  val = fields.active;
  void 0 === val && (val = !0);
  val && (bits += 4);
  val = fields.write;
  void 0 === val && (val = !0);
  val && (bits += 8);
  val = fields.read;
  void 0 === val && (val = !0);
  val && (bits += 16);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeAccessRequestOk(buffer) {
  var val, offset = 0, fields = {
    ticket: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  return fields;
}

function encodeAccessRequestOk(channel, fields) {
  var offset = 0, val = null, buffer = Buffer.alloc(14);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(1966091, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 1; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeDeclare(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    exchange: void 0,
    type: void 0,
    passive: void 0,
    durable: void 0,
    autoDelete: void 0,
    internal: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.type = val;
  val = !!(1 & buffer[offset]);
  fields.passive = val;
  val = !!(2 & buffer[offset]);
  fields.durable = val;
  val = !!(4 & buffer[offset]);
  fields.autoDelete = val;
  val = !!(8 & buffer[offset]);
  fields.internal = val;
  val = !!(16 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeExchangeDeclare(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.type;
  if (void 0 === val) val = "direct"; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'type' is the wrong type; must be a string (up to 255 chars)");
  var type_len = Buffer.byteLength(val, "utf8");
  varyingSize += type_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621450, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.type;
  void 0 === val && (val = "direct");
  buffer[offset] = type_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += type_len;
  val = fields.passive;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.durable;
  void 0 === val && (val = !1);
  val && (bits += 2);
  val = fields.autoDelete;
  void 0 === val && (val = !1);
  val && (bits += 4);
  val = fields.internal;
  void 0 === val && (val = !1);
  val && (bits += 8);
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 16);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeDeclareOk(buffer) {
  return {};
}

function encodeExchangeDeclareOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621451, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeDelete(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    exchange: void 0,
    ifUnused: void 0,
    nowait: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  val = !!(1 & buffer[offset]);
  fields.ifUnused = val;
  val = !!(2 & buffer[offset]);
  fields.nowait = val;
  return fields;
}

function encodeExchangeDelete(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621460, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.ifUnused;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 2);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeDeleteOk(buffer) {
  return {};
}

function encodeExchangeDeleteOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621461, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeBind(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    destination: void 0,
    source: void 0,
    routingKey: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.destination = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.source = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  val = !!(1 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeExchangeBind(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.destination;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'destination'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'destination' is the wrong type; must be a string (up to 255 chars)");
  var destination_len = Buffer.byteLength(val, "utf8");
  varyingSize += destination_len;
  val = fields.source;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'source'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'source' is the wrong type; must be a string (up to 255 chars)");
  var source_len = Buffer.byteLength(val, "utf8");
  varyingSize += source_len;
  val = fields.routingKey;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(18 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621470, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.destination;
  void 0 === val && (val = void 0);
  buffer[offset] = destination_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += destination_len;
  val = fields.source;
  void 0 === val && (val = void 0);
  buffer[offset] = source_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += source_len;
  val = fields.routingKey;
  void 0 === val && (val = "");
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeBindOk(buffer) {
  return {};
}

function encodeExchangeBindOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621471, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeUnbind(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    destination: void 0,
    source: void 0,
    routingKey: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.destination = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.source = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  val = !!(1 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeExchangeUnbind(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.destination;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'destination'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'destination' is the wrong type; must be a string (up to 255 chars)");
  var destination_len = Buffer.byteLength(val, "utf8");
  varyingSize += destination_len;
  val = fields.source;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'source'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'source' is the wrong type; must be a string (up to 255 chars)");
  var source_len = Buffer.byteLength(val, "utf8");
  varyingSize += source_len;
  val = fields.routingKey;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(18 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621480, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.destination;
  void 0 === val && (val = void 0);
  buffer[offset] = destination_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += destination_len;
  val = fields.source;
  void 0 === val && (val = void 0);
  buffer[offset] = source_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += source_len;
  val = fields.routingKey;
  void 0 === val && (val = "");
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeExchangeUnbindOk(buffer) {
  return {};
}

function encodeExchangeUnbindOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(2621491, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueDeclare(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    passive: void 0,
    durable: void 0,
    exclusive: void 0,
    autoDelete: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  val = !!(1 & buffer[offset]);
  fields.passive = val;
  val = !!(2 & buffer[offset]);
  fields.durable = val;
  val = !!(4 & buffer[offset]);
  fields.exclusive = val;
  val = !!(8 & buffer[offset]);
  fields.autoDelete = val;
  val = !!(16 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeQueueDeclare(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276810, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.passive;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.durable;
  void 0 === val && (val = !1);
  val && (bits += 2);
  val = fields.exclusive;
  void 0 === val && (val = !1);
  val && (bits += 4);
  val = fields.autoDelete;
  void 0 === val && (val = !1);
  val && (bits += 8);
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 16);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueDeclareOk(buffer) {
  var val, len, offset = 0, fields = {
    queue: void 0,
    messageCount: void 0,
    consumerCount: void 0
  };
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.messageCount = val;
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.consumerCount = val;
  return fields;
}

function encodeQueueDeclareOk(channel, fields) {
  var offset = 0, val = null, varyingSize = 0;
  val = fields.queue;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'queue'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  var buffer = Buffer.alloc(21 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276811, 7);
  offset = 11;
  val = fields.queue;
  void 0 === val && (val = void 0);
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.messageCount;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'messageCount'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'messageCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  val = fields.consumerCount;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'consumerCount'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'consumerCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueBind(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    exchange: void 0,
    routingKey: void 0,
    nowait: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  val = !!(1 & buffer[offset]);
  fields.nowait = val;
  offset++;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeQueueBind(channel, fields) {
  var len, offset = 0, val = null, bits = 0, varyingSize = 0, scratchOffset = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(18 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276820, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = "");
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  bits = 0;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueBindOk(buffer) {
  return {};
}

function encodeQueueBindOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276821, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueuePurge(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    nowait: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  val = !!(1 & buffer[offset]);
  fields.nowait = val;
  return fields;
}

function encodeQueuePurge(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276830, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueuePurgeOk(buffer) {
  var val, offset = 0, fields = {
    messageCount: void 0
  };
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.messageCount = val;
  return fields;
}

function encodeQueuePurgeOk(channel, fields) {
  var offset = 0, val = null, buffer = Buffer.alloc(16);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276831, 7);
  offset = 11;
  val = fields.messageCount;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'messageCount'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'messageCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueDelete(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    ifUnused: void 0,
    ifEmpty: void 0,
    nowait: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  val = !!(1 & buffer[offset]);
  fields.ifUnused = val;
  val = !!(2 & buffer[offset]);
  fields.ifEmpty = val;
  val = !!(4 & buffer[offset]);
  fields.nowait = val;
  return fields;
}

function encodeQueueDelete(channel, fields) {
  var offset = 0, val = null, bits = 0, varyingSize = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  var buffer = Buffer.alloc(16 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276840, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.ifUnused;
  void 0 === val && (val = !1);
  val && (bits += 1);
  val = fields.ifEmpty;
  void 0 === val && (val = !1);
  val && (bits += 2);
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 4);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueDeleteOk(buffer) {
  var val, offset = 0, fields = {
    messageCount: void 0
  };
  val = buffer.readUInt32BE(offset);
  offset += 4;
  fields.messageCount = val;
  return fields;
}

function encodeQueueDeleteOk(channel, fields) {
  var offset = 0, val = null, buffer = Buffer.alloc(16);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276841, 7);
  offset = 11;
  val = fields.messageCount;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'messageCount'");
  if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'messageCount' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt32BE(val, offset);
  offset += 4;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueUnbind(buffer) {
  var val, len, offset = 0, fields = {
    ticket: void 0,
    queue: void 0,
    exchange: void 0,
    routingKey: void 0,
    arguments: void 0
  };
  val = buffer.readUInt16BE(offset);
  offset += 2;
  fields.ticket = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.queue = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.exchange = val;
  len = buffer.readUInt8(offset);
  offset++;
  val = buffer.toString("utf8", offset, offset + len);
  offset += len;
  fields.routingKey = val;
  len = buffer.readUInt32BE(offset);
  offset += 4;
  val = decodeFields(buffer.subarray(offset, offset + len));
  offset += len;
  fields.arguments = val;
  return fields;
}

function encodeQueueUnbind(channel, fields) {
  var len, offset = 0, val = null, varyingSize = 0, scratchOffset = 0;
  val = fields.queue;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'queue' is the wrong type; must be a string (up to 255 chars)");
  var queue_len = Buffer.byteLength(val, "utf8");
  varyingSize += queue_len;
  val = fields.exchange;
  if (void 0 === val) throw new Error("Missing value for mandatory field 'exchange'");
  if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'exchange' is the wrong type; must be a string (up to 255 chars)");
  var exchange_len = Buffer.byteLength(val, "utf8");
  varyingSize += exchange_len;
  val = fields.routingKey;
  if (void 0 === val) val = ""; else if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'routingKey' is the wrong type; must be a string (up to 255 chars)");
  var routingKey_len = Buffer.byteLength(val, "utf8");
  varyingSize += routingKey_len;
  val = fields.arguments;
  if (void 0 === val) val = {}; else if ("object" != typeof val) throw new TypeError("Field 'arguments' is the wrong type; must be an object");
  len = encodeTable(SCRATCH, val, scratchOffset);
  var arguments_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
  scratchOffset += len;
  varyingSize += arguments_encoded.length;
  var buffer = Buffer.alloc(17 + varyingSize);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276850, 7);
  offset = 11;
  val = fields.ticket;
  if (void 0 === val) val = 0; else if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'ticket' is the wrong type; must be a number (but not NaN)");
  buffer.writeUInt16BE(val, offset);
  offset += 2;
  val = fields.queue;
  void 0 === val && (val = "");
  buffer[offset] = queue_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += queue_len;
  val = fields.exchange;
  void 0 === val && (val = void 0);
  buffer[offset] = exchange_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += exchange_len;
  val = fields.routingKey;
  void 0 === val && (val = "");
  buffer[offset] = routingKey_len;
  offset++;
  buffer.write(val, offset, "utf8");
  offset += routingKey_len;
  offset += arguments_encoded.copy(buffer, offset);
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeQueueUnbindOk(buffer) {
  return {};
}

function encodeQueueUnbindOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3276851, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxSelect(buffer) {
  return {};
}

function encodeTxSelect(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898250, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxSelectOk(buffer) {
  return {};
}

function encodeTxSelectOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898251, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxCommit(buffer) {
  return {};
}

function encodeTxCommit(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898260, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxCommitOk(buffer) {
  return {};
}

function encodeTxCommitOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898261, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxRollback(buffer) {
  return {};
}

function encodeTxRollback(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898270, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeTxRollbackOk(buffer) {
  return {};
}

function encodeTxRollbackOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5898271, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConfirmSelect(buffer) {
  var val, fields = {
    nowait: void 0
  };
  val = !!(1 & buffer[0]);
  fields.nowait = val;
  return fields;
}

function encodeConfirmSelect(channel, fields) {
  var offset = 0, val = null, bits = 0, buffer = Buffer.alloc(13);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5570570, 7);
  offset = 11;
  val = fields.nowait;
  void 0 === val && (val = !1);
  val && (bits += 1);
  buffer[offset] = bits;
  offset++;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function decodeConfirmSelectOk(buffer) {
  return {};
}

function encodeConfirmSelectOk(channel, fields) {
  var offset = 0, buffer = Buffer.alloc(12);
  buffer[0] = 1;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(5570571, 7);
  offset = 11;
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  return buffer;
}

function encodeBasicProperties(channel, size, fields) {
  var val, len, offset = 0, flags = 0, scratchOffset = 0, varyingSize = 0;
  val = fields.contentType;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'contentType' is the wrong type; must be a string (up to 255 chars)");
    var contentType_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += contentType_len;
  }
  val = fields.contentEncoding;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'contentEncoding' is the wrong type; must be a string (up to 255 chars)");
    var contentEncoding_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += contentEncoding_len;
  }
  val = fields.headers;
  if (void 0 != val) {
    if ("object" != typeof val) throw new TypeError("Field 'headers' is the wrong type; must be an object");
    len = encodeTable(SCRATCH, val, scratchOffset);
    var headers_encoded = SCRATCH.slice(scratchOffset, scratchOffset + len);
    scratchOffset += len;
    varyingSize += headers_encoded.length;
  }
  val = fields.deliveryMode;
  if (void 0 != val) {
    if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'deliveryMode' is the wrong type; must be a number (but not NaN)");
    varyingSize += 1;
  }
  val = fields.priority;
  if (void 0 != val) {
    if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'priority' is the wrong type; must be a number (but not NaN)");
    varyingSize += 1;
  }
  val = fields.correlationId;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'correlationId' is the wrong type; must be a string (up to 255 chars)");
    var correlationId_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += correlationId_len;
  }
  val = fields.replyTo;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'replyTo' is the wrong type; must be a string (up to 255 chars)");
    var replyTo_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += replyTo_len;
  }
  val = fields.expiration;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'expiration' is the wrong type; must be a string (up to 255 chars)");
    var expiration_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += expiration_len;
  }
  val = fields.messageId;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'messageId' is the wrong type; must be a string (up to 255 chars)");
    var messageId_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += messageId_len;
  }
  val = fields.timestamp;
  if (void 0 != val) {
    if ("number" != typeof val || isNaN(val)) throw new TypeError("Field 'timestamp' is the wrong type; must be a number (but not NaN)");
    varyingSize += 8;
  }
  val = fields.type;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'type' is the wrong type; must be a string (up to 255 chars)");
    var type_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += type_len;
  }
  val = fields.userId;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'userId' is the wrong type; must be a string (up to 255 chars)");
    var userId_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += userId_len;
  }
  val = fields.appId;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'appId' is the wrong type; must be a string (up to 255 chars)");
    var appId_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += appId_len;
  }
  val = fields.clusterId;
  if (void 0 != val) {
    if (!("string" == typeof val && Buffer.byteLength(val) < 256)) throw new TypeError("Field 'clusterId' is the wrong type; must be a string (up to 255 chars)");
    var clusterId_len = Buffer.byteLength(val, "utf8");
    varyingSize += 1;
    varyingSize += clusterId_len;
  }
  var buffer = Buffer.alloc(22 + varyingSize);
  buffer[0] = 2;
  buffer.writeUInt16BE(channel, 1);
  buffer.writeUInt32BE(3932160, 7);
  ints$1.writeUInt64BE(buffer, size, 11);
  flags = 0;
  offset = 21;
  val = fields.contentType;
  if (void 0 != val) {
    flags += 32768;
    buffer[offset] = contentType_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += contentType_len;
  }
  val = fields.contentEncoding;
  if (void 0 != val) {
    flags += 16384;
    buffer[offset] = contentEncoding_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += contentEncoding_len;
  }
  val = fields.headers;
  if (void 0 != val) {
    flags += 8192;
    offset += headers_encoded.copy(buffer, offset);
  }
  val = fields.deliveryMode;
  if (void 0 != val) {
    flags += 4096;
    buffer.writeUInt8(val, offset);
    offset++;
  }
  val = fields.priority;
  if (void 0 != val) {
    flags += 2048;
    buffer.writeUInt8(val, offset);
    offset++;
  }
  val = fields.correlationId;
  if (void 0 != val) {
    flags += 1024;
    buffer[offset] = correlationId_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += correlationId_len;
  }
  val = fields.replyTo;
  if (void 0 != val) {
    flags += 512;
    buffer[offset] = replyTo_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += replyTo_len;
  }
  val = fields.expiration;
  if (void 0 != val) {
    flags += 256;
    buffer[offset] = expiration_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += expiration_len;
  }
  val = fields.messageId;
  if (void 0 != val) {
    flags += 128;
    buffer[offset] = messageId_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += messageId_len;
  }
  val = fields.timestamp;
  if (void 0 != val) {
    flags += 64;
    ints$1.writeUInt64BE(buffer, val, offset);
    offset += 8;
  }
  val = fields.type;
  if (void 0 != val) {
    flags += 32;
    buffer[offset] = type_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += type_len;
  }
  val = fields.userId;
  if (void 0 != val) {
    flags += 16;
    buffer[offset] = userId_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += userId_len;
  }
  val = fields.appId;
  if (void 0 != val) {
    flags += 8;
    buffer[offset] = appId_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += appId_len;
  }
  val = fields.clusterId;
  if (void 0 != val) {
    flags += 4;
    buffer[offset] = clusterId_len;
    offset++;
    buffer.write(val, offset, "utf8");
    offset += clusterId_len;
  }
  buffer[offset] = 206;
  buffer.writeUInt32BE(offset - 7, 3);
  buffer.writeUInt16BE(flags, 19);
  return buffer.subarray(0, offset + 1);
}

function decodeBasicProperties(buffer) {
  var flags, val, len, offset = 2;
  flags = buffer.readUInt16BE(0);
  if (0 === flags) return {};
  var fields = {
    contentType: void 0,
    contentEncoding: void 0,
    headers: void 0,
    deliveryMode: void 0,
    priority: void 0,
    correlationId: void 0,
    replyTo: void 0,
    expiration: void 0,
    messageId: void 0,
    timestamp: void 0,
    type: void 0,
    userId: void 0,
    appId: void 0,
    clusterId: void 0
  };
  if (32768 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.contentType = val;
  }
  if (16384 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.contentEncoding = val;
  }
  if (8192 & flags) {
    len = buffer.readUInt32BE(offset);
    offset += 4;
    val = decodeFields(buffer.subarray(offset, offset + len));
    offset += len;
    fields.headers = val;
  }
  if (4096 & flags) {
    val = buffer[offset];
    offset++;
    fields.deliveryMode = val;
  }
  if (2048 & flags) {
    val = buffer[offset];
    offset++;
    fields.priority = val;
  }
  if (1024 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.correlationId = val;
  }
  if (512 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.replyTo = val;
  }
  if (256 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.expiration = val;
  }
  if (128 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.messageId = val;
  }
  if (64 & flags) {
    val = ints$1.readUInt64BE(buffer, offset);
    offset += 8;
    fields.timestamp = val;
  }
  if (32 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.type = val;
  }
  if (16 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.userId = val;
  }
  if (8 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.appId = val;
  }
  if (4 & flags) {
    len = buffer.readUInt8(offset);
    offset++;
    val = buffer.toString("utf8", offset, offset + len);
    offset += len;
    fields.clusterId = val;
  }
  return fields;
}

var codec$1 = codec$2, ints$1 = bufferMoreIntsExports, encodeTable = codec$1.encodeTable, decodeFields = codec$1.decodeFields, SCRATCH = Buffer.alloc(65536);

defs$5.constants = {
  FRAME_METHOD: 1,
  FRAME_HEADER: 2,
  FRAME_BODY: 3,
  FRAME_HEARTBEAT: 8,
  FRAME_MIN_SIZE: 4096,
  FRAME_END: 206,
  REPLY_SUCCESS: 200,
  CONTENT_TOO_LARGE: 311,
  NO_ROUTE: 312,
  NO_CONSUMERS: 313,
  ACCESS_REFUSED: 403,
  NOT_FOUND: 404,
  RESOURCE_LOCKED: 405,
  PRECONDITION_FAILED: 406,
  CONNECTION_FORCED: 320,
  INVALID_PATH: 402,
  FRAME_ERROR: 501,
  SYNTAX_ERROR: 502,
  COMMAND_INVALID: 503,
  CHANNEL_ERROR: 504,
  UNEXPECTED_FRAME: 505,
  RESOURCE_ERROR: 506,
  NOT_ALLOWED: 530,
  NOT_IMPLEMENTED: 540,
  INTERNAL_ERROR: 541
};

defs$5.constant_strs = {
  "1": "FRAME-METHOD",
  "2": "FRAME-HEADER",
  "3": "FRAME-BODY",
  "8": "FRAME-HEARTBEAT",
  "200": "REPLY-SUCCESS",
  "206": "FRAME-END",
  "311": "CONTENT-TOO-LARGE",
  "312": "NO-ROUTE",
  "313": "NO-CONSUMERS",
  "320": "CONNECTION-FORCED",
  "402": "INVALID-PATH",
  "403": "ACCESS-REFUSED",
  "404": "NOT-FOUND",
  "405": "RESOURCE-LOCKED",
  "406": "PRECONDITION-FAILED",
  "501": "FRAME-ERROR",
  "502": "SYNTAX-ERROR",
  "503": "COMMAND-INVALID",
  "504": "CHANNEL-ERROR",
  "505": "UNEXPECTED-FRAME",
  "506": "RESOURCE-ERROR",
  "530": "NOT-ALLOWED",
  "540": "NOT-IMPLEMENTED",
  "541": "INTERNAL-ERROR",
  "4096": "FRAME-MIN-SIZE"
};

defs$5.FRAME_OVERHEAD = 8;

defs$5.decode = function(id, buf) {
  switch (id) {
   case 3932170:
    return decodeBasicQos(buf);

   case 3932171:
    return decodeBasicQosOk();

   case 3932180:
    return decodeBasicConsume(buf);

   case 3932181:
    return decodeBasicConsumeOk(buf);

   case 3932190:
    return decodeBasicCancel(buf);

   case 3932191:
    return decodeBasicCancelOk(buf);

   case 3932200:
    return decodeBasicPublish(buf);

   case 3932210:
    return decodeBasicReturn(buf);

   case 3932220:
    return decodeBasicDeliver(buf);

   case 3932230:
    return decodeBasicGet(buf);

   case 3932231:
    return decodeBasicGetOk(buf);

   case 3932232:
    return decodeBasicGetEmpty(buf);

   case 3932240:
    return decodeBasicAck(buf);

   case 3932250:
    return decodeBasicReject(buf);

   case 3932260:
    return decodeBasicRecoverAsync(buf);

   case 3932270:
    return decodeBasicRecover(buf);

   case 3932271:
    return decodeBasicRecoverOk();

   case 3932280:
    return decodeBasicNack(buf);

   case 655370:
    return decodeConnectionStart(buf);

   case 655371:
    return decodeConnectionStartOk(buf);

   case 655380:
    return decodeConnectionSecure(buf);

   case 655381:
    return decodeConnectionSecureOk(buf);

   case 655390:
    return decodeConnectionTune(buf);

   case 655391:
    return decodeConnectionTuneOk(buf);

   case 655400:
    return decodeConnectionOpen(buf);

   case 655401:
    return decodeConnectionOpenOk(buf);

   case 655410:
    return decodeConnectionClose(buf);

   case 655411:
    return decodeConnectionCloseOk();

   case 655420:
    return decodeConnectionBlocked(buf);

   case 655421:
    return decodeConnectionUnblocked();

   case 655430:
    return decodeConnectionUpdateSecret(buf);

   case 655431:
    return decodeConnectionUpdateSecretOk();

   case 1310730:
    return decodeChannelOpen(buf);

   case 1310731:
    return decodeChannelOpenOk(buf);

   case 1310740:
    return decodeChannelFlow(buf);

   case 1310741:
    return decodeChannelFlowOk(buf);

   case 1310760:
    return decodeChannelClose(buf);

   case 1310761:
    return decodeChannelCloseOk();

   case 1966090:
    return decodeAccessRequest(buf);

   case 1966091:
    return decodeAccessRequestOk(buf);

   case 2621450:
    return decodeExchangeDeclare(buf);

   case 2621451:
    return decodeExchangeDeclareOk();

   case 2621460:
    return decodeExchangeDelete(buf);

   case 2621461:
    return decodeExchangeDeleteOk();

   case 2621470:
    return decodeExchangeBind(buf);

   case 2621471:
    return decodeExchangeBindOk();

   case 2621480:
    return decodeExchangeUnbind(buf);

   case 2621491:
    return decodeExchangeUnbindOk();

   case 3276810:
    return decodeQueueDeclare(buf);

   case 3276811:
    return decodeQueueDeclareOk(buf);

   case 3276820:
    return decodeQueueBind(buf);

   case 3276821:
    return decodeQueueBindOk();

   case 3276830:
    return decodeQueuePurge(buf);

   case 3276831:
    return decodeQueuePurgeOk(buf);

   case 3276840:
    return decodeQueueDelete(buf);

   case 3276841:
    return decodeQueueDeleteOk(buf);

   case 3276850:
    return decodeQueueUnbind(buf);

   case 3276851:
    return decodeQueueUnbindOk();

   case 5898250:
    return decodeTxSelect();

   case 5898251:
    return decodeTxSelectOk();

   case 5898260:
    return decodeTxCommit();

   case 5898261:
    return decodeTxCommitOk();

   case 5898270:
    return decodeTxRollback();

   case 5898271:
    return decodeTxRollbackOk();

   case 5570570:
    return decodeConfirmSelect(buf);

   case 5570571:
    return decodeConfirmSelectOk();

   case 60:
    return decodeBasicProperties(buf);

   default:
    throw new Error("Unknown class/method ID");
  }
};

defs$5.encodeMethod = function(id, channel, fields) {
  switch (id) {
   case 3932170:
    return encodeBasicQos(channel, fields);

   case 3932171:
    return encodeBasicQosOk(channel);

   case 3932180:
    return encodeBasicConsume(channel, fields);

   case 3932181:
    return encodeBasicConsumeOk(channel, fields);

   case 3932190:
    return encodeBasicCancel(channel, fields);

   case 3932191:
    return encodeBasicCancelOk(channel, fields);

   case 3932200:
    return encodeBasicPublish(channel, fields);

   case 3932210:
    return encodeBasicReturn(channel, fields);

   case 3932220:
    return encodeBasicDeliver(channel, fields);

   case 3932230:
    return encodeBasicGet(channel, fields);

   case 3932231:
    return encodeBasicGetOk(channel, fields);

   case 3932232:
    return encodeBasicGetEmpty(channel, fields);

   case 3932240:
    return encodeBasicAck(channel, fields);

   case 3932250:
    return encodeBasicReject(channel, fields);

   case 3932260:
    return encodeBasicRecoverAsync(channel, fields);

   case 3932270:
    return encodeBasicRecover(channel, fields);

   case 3932271:
    return encodeBasicRecoverOk(channel);

   case 3932280:
    return encodeBasicNack(channel, fields);

   case 655370:
    return encodeConnectionStart(channel, fields);

   case 655371:
    return encodeConnectionStartOk(channel, fields);

   case 655380:
    return encodeConnectionSecure(channel, fields);

   case 655381:
    return encodeConnectionSecureOk(channel, fields);

   case 655390:
    return encodeConnectionTune(channel, fields);

   case 655391:
    return encodeConnectionTuneOk(channel, fields);

   case 655400:
    return encodeConnectionOpen(channel, fields);

   case 655401:
    return encodeConnectionOpenOk(channel, fields);

   case 655410:
    return encodeConnectionClose(channel, fields);

   case 655411:
    return encodeConnectionCloseOk(channel);

   case 655420:
    return encodeConnectionBlocked(channel, fields);

   case 655421:
    return encodeConnectionUnblocked(channel);

   case 655430:
    return encodeConnectionUpdateSecret(channel, fields);

   case 655431:
    return encodeConnectionUpdateSecretOk(channel);

   case 1310730:
    return encodeChannelOpen(channel, fields);

   case 1310731:
    return encodeChannelOpenOk(channel, fields);

   case 1310740:
    return encodeChannelFlow(channel, fields);

   case 1310741:
    return encodeChannelFlowOk(channel, fields);

   case 1310760:
    return encodeChannelClose(channel, fields);

   case 1310761:
    return encodeChannelCloseOk(channel);

   case 1966090:
    return encodeAccessRequest(channel, fields);

   case 1966091:
    return encodeAccessRequestOk(channel, fields);

   case 2621450:
    return encodeExchangeDeclare(channel, fields);

   case 2621451:
    return encodeExchangeDeclareOk(channel);

   case 2621460:
    return encodeExchangeDelete(channel, fields);

   case 2621461:
    return encodeExchangeDeleteOk(channel);

   case 2621470:
    return encodeExchangeBind(channel, fields);

   case 2621471:
    return encodeExchangeBindOk(channel);

   case 2621480:
    return encodeExchangeUnbind(channel, fields);

   case 2621491:
    return encodeExchangeUnbindOk(channel);

   case 3276810:
    return encodeQueueDeclare(channel, fields);

   case 3276811:
    return encodeQueueDeclareOk(channel, fields);

   case 3276820:
    return encodeQueueBind(channel, fields);

   case 3276821:
    return encodeQueueBindOk(channel);

   case 3276830:
    return encodeQueuePurge(channel, fields);

   case 3276831:
    return encodeQueuePurgeOk(channel, fields);

   case 3276840:
    return encodeQueueDelete(channel, fields);

   case 3276841:
    return encodeQueueDeleteOk(channel, fields);

   case 3276850:
    return encodeQueueUnbind(channel, fields);

   case 3276851:
    return encodeQueueUnbindOk(channel);

   case 5898250:
    return encodeTxSelect(channel);

   case 5898251:
    return encodeTxSelectOk(channel);

   case 5898260:
    return encodeTxCommit(channel);

   case 5898261:
    return encodeTxCommitOk(channel);

   case 5898270:
    return encodeTxRollback(channel);

   case 5898271:
    return encodeTxRollbackOk(channel);

   case 5570570:
    return encodeConfirmSelect(channel, fields);

   case 5570571:
    return encodeConfirmSelectOk(channel);

   default:
    throw new Error("Unknown class/method ID");
  }
};

defs$5.encodeProperties = function(id, channel, size, fields) {
  switch (id) {
   case 60:
    return encodeBasicProperties(channel, size, fields);

   default:
    throw new Error("Unknown class/properties ID");
  }
};

defs$5.info = function(id) {
  switch (id) {
   case 3932170:
    return methodInfoBasicQos;

   case 3932171:
    return methodInfoBasicQosOk;

   case 3932180:
    return methodInfoBasicConsume;

   case 3932181:
    return methodInfoBasicConsumeOk;

   case 3932190:
    return methodInfoBasicCancel;

   case 3932191:
    return methodInfoBasicCancelOk;

   case 3932200:
    return methodInfoBasicPublish;

   case 3932210:
    return methodInfoBasicReturn;

   case 3932220:
    return methodInfoBasicDeliver;

   case 3932230:
    return methodInfoBasicGet;

   case 3932231:
    return methodInfoBasicGetOk;

   case 3932232:
    return methodInfoBasicGetEmpty;

   case 3932240:
    return methodInfoBasicAck;

   case 3932250:
    return methodInfoBasicReject;

   case 3932260:
    return methodInfoBasicRecoverAsync;

   case 3932270:
    return methodInfoBasicRecover;

   case 3932271:
    return methodInfoBasicRecoverOk;

   case 3932280:
    return methodInfoBasicNack;

   case 655370:
    return methodInfoConnectionStart;

   case 655371:
    return methodInfoConnectionStartOk;

   case 655380:
    return methodInfoConnectionSecure;

   case 655381:
    return methodInfoConnectionSecureOk;

   case 655390:
    return methodInfoConnectionTune;

   case 655391:
    return methodInfoConnectionTuneOk;

   case 655400:
    return methodInfoConnectionOpen;

   case 655401:
    return methodInfoConnectionOpenOk;

   case 655410:
    return methodInfoConnectionClose;

   case 655411:
    return methodInfoConnectionCloseOk;

   case 655420:
    return methodInfoConnectionBlocked;

   case 655421:
    return methodInfoConnectionUnblocked;

   case 655430:
    return methodInfoConnectionUpdateSecret;

   case 655431:
    return methodInfoConnectionUpdateSecretOk;

   case 1310730:
    return methodInfoChannelOpen;

   case 1310731:
    return methodInfoChannelOpenOk;

   case 1310740:
    return methodInfoChannelFlow;

   case 1310741:
    return methodInfoChannelFlowOk;

   case 1310760:
    return methodInfoChannelClose;

   case 1310761:
    return methodInfoChannelCloseOk;

   case 1966090:
    return methodInfoAccessRequest;

   case 1966091:
    return methodInfoAccessRequestOk;

   case 2621450:
    return methodInfoExchangeDeclare;

   case 2621451:
    return methodInfoExchangeDeclareOk;

   case 2621460:
    return methodInfoExchangeDelete;

   case 2621461:
    return methodInfoExchangeDeleteOk;

   case 2621470:
    return methodInfoExchangeBind;

   case 2621471:
    return methodInfoExchangeBindOk;

   case 2621480:
    return methodInfoExchangeUnbind;

   case 2621491:
    return methodInfoExchangeUnbindOk;

   case 3276810:
    return methodInfoQueueDeclare;

   case 3276811:
    return methodInfoQueueDeclareOk;

   case 3276820:
    return methodInfoQueueBind;

   case 3276821:
    return methodInfoQueueBindOk;

   case 3276830:
    return methodInfoQueuePurge;

   case 3276831:
    return methodInfoQueuePurgeOk;

   case 3276840:
    return methodInfoQueueDelete;

   case 3276841:
    return methodInfoQueueDeleteOk;

   case 3276850:
    return methodInfoQueueUnbind;

   case 3276851:
    return methodInfoQueueUnbindOk;

   case 5898250:
    return methodInfoTxSelect;

   case 5898251:
    return methodInfoTxSelectOk;

   case 5898260:
    return methodInfoTxCommit;

   case 5898261:
    return methodInfoTxCommitOk;

   case 5898270:
    return methodInfoTxRollback;

   case 5898271:
    return methodInfoTxRollbackOk;

   case 5570570:
    return methodInfoConfirmSelect;

   case 5570571:
    return methodInfoConfirmSelectOk;

   case 60:
    return propertiesInfoBasicProperties;

   default:
    throw new Error("Unknown class/method ID");
  }
};

defs$5.BasicQos = 3932170;

var methodInfoBasicQos = defs$5.methodInfoBasicQos = {
  id: 3932170,
  classId: 60,
  methodId: 10,
  name: "BasicQos",
  args: [ {
    type: "long",
    name: "prefetchSize",
    default: 0
  }, {
    type: "short",
    name: "prefetchCount",
    default: 0
  }, {
    type: "bit",
    name: "global",
    default: !1
  } ]
};

defs$5.BasicQosOk = 3932171;

var methodInfoBasicQosOk = defs$5.methodInfoBasicQosOk = {
  id: 3932171,
  classId: 60,
  methodId: 11,
  name: "BasicQosOk",
  args: []
};

defs$5.BasicConsume = 3932180;

var methodInfoBasicConsume = defs$5.methodInfoBasicConsume = {
  id: 3932180,
  classId: 60,
  methodId: 20,
  name: "BasicConsume",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "shortstr",
    name: "consumerTag",
    default: ""
  }, {
    type: "bit",
    name: "noLocal",
    default: !1
  }, {
    type: "bit",
    name: "noAck",
    default: !1
  }, {
    type: "bit",
    name: "exclusive",
    default: !1
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.BasicConsumeOk = 3932181;

var methodInfoBasicConsumeOk = defs$5.methodInfoBasicConsumeOk = {
  id: 3932181,
  classId: 60,
  methodId: 21,
  name: "BasicConsumeOk",
  args: [ {
    type: "shortstr",
    name: "consumerTag"
  } ]
};

defs$5.BasicCancel = 3932190;

var methodInfoBasicCancel = defs$5.methodInfoBasicCancel = {
  id: 3932190,
  classId: 60,
  methodId: 30,
  name: "BasicCancel",
  args: [ {
    type: "shortstr",
    name: "consumerTag"
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  } ]
};

defs$5.BasicCancelOk = 3932191;

var methodInfoBasicCancelOk = defs$5.methodInfoBasicCancelOk = {
  id: 3932191,
  classId: 60,
  methodId: 31,
  name: "BasicCancelOk",
  args: [ {
    type: "shortstr",
    name: "consumerTag"
  } ]
};

defs$5.BasicPublish = 3932200;

var methodInfoBasicPublish = defs$5.methodInfoBasicPublish = {
  id: 3932200,
  classId: 60,
  methodId: 40,
  name: "BasicPublish",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "exchange",
    default: ""
  }, {
    type: "shortstr",
    name: "routingKey",
    default: ""
  }, {
    type: "bit",
    name: "mandatory",
    default: !1
  }, {
    type: "bit",
    name: "immediate",
    default: !1
  } ]
};

defs$5.BasicReturn = 3932210;

var methodInfoBasicReturn = defs$5.methodInfoBasicReturn = {
  id: 3932210,
  classId: 60,
  methodId: 50,
  name: "BasicReturn",
  args: [ {
    type: "short",
    name: "replyCode"
  }, {
    type: "shortstr",
    name: "replyText",
    default: ""
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "routingKey"
  } ]
};

defs$5.BasicDeliver = 3932220;

var methodInfoBasicDeliver = defs$5.methodInfoBasicDeliver = {
  id: 3932220,
  classId: 60,
  methodId: 60,
  name: "BasicDeliver",
  args: [ {
    type: "shortstr",
    name: "consumerTag"
  }, {
    type: "longlong",
    name: "deliveryTag"
  }, {
    type: "bit",
    name: "redelivered",
    default: !1
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "routingKey"
  } ]
};

defs$5.BasicGet = 3932230;

var methodInfoBasicGet = defs$5.methodInfoBasicGet = {
  id: 3932230,
  classId: 60,
  methodId: 70,
  name: "BasicGet",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "bit",
    name: "noAck",
    default: !1
  } ]
};

defs$5.BasicGetOk = 3932231;

var methodInfoBasicGetOk = defs$5.methodInfoBasicGetOk = {
  id: 3932231,
  classId: 60,
  methodId: 71,
  name: "BasicGetOk",
  args: [ {
    type: "longlong",
    name: "deliveryTag"
  }, {
    type: "bit",
    name: "redelivered",
    default: !1
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "routingKey"
  }, {
    type: "long",
    name: "messageCount"
  } ]
};

defs$5.BasicGetEmpty = 3932232;

var methodInfoBasicGetEmpty = defs$5.methodInfoBasicGetEmpty = {
  id: 3932232,
  classId: 60,
  methodId: 72,
  name: "BasicGetEmpty",
  args: [ {
    type: "shortstr",
    name: "clusterId",
    default: ""
  } ]
};

defs$5.BasicAck = 3932240;

var methodInfoBasicAck = defs$5.methodInfoBasicAck = {
  id: 3932240,
  classId: 60,
  methodId: 80,
  name: "BasicAck",
  args: [ {
    type: "longlong",
    name: "deliveryTag",
    default: 0
  }, {
    type: "bit",
    name: "multiple",
    default: !1
  } ]
};

defs$5.BasicReject = 3932250;

var methodInfoBasicReject = defs$5.methodInfoBasicReject = {
  id: 3932250,
  classId: 60,
  methodId: 90,
  name: "BasicReject",
  args: [ {
    type: "longlong",
    name: "deliveryTag"
  }, {
    type: "bit",
    name: "requeue",
    default: !0
  } ]
};

defs$5.BasicRecoverAsync = 3932260;

var methodInfoBasicRecoverAsync = defs$5.methodInfoBasicRecoverAsync = {
  id: 3932260,
  classId: 60,
  methodId: 100,
  name: "BasicRecoverAsync",
  args: [ {
    type: "bit",
    name: "requeue",
    default: !1
  } ]
};

defs$5.BasicRecover = 3932270;

var methodInfoBasicRecover = defs$5.methodInfoBasicRecover = {
  id: 3932270,
  classId: 60,
  methodId: 110,
  name: "BasicRecover",
  args: [ {
    type: "bit",
    name: "requeue",
    default: !1
  } ]
};

defs$5.BasicRecoverOk = 3932271;

var methodInfoBasicRecoverOk = defs$5.methodInfoBasicRecoverOk = {
  id: 3932271,
  classId: 60,
  methodId: 111,
  name: "BasicRecoverOk",
  args: []
};

defs$5.BasicNack = 3932280;

var methodInfoBasicNack = defs$5.methodInfoBasicNack = {
  id: 3932280,
  classId: 60,
  methodId: 120,
  name: "BasicNack",
  args: [ {
    type: "longlong",
    name: "deliveryTag",
    default: 0
  }, {
    type: "bit",
    name: "multiple",
    default: !1
  }, {
    type: "bit",
    name: "requeue",
    default: !0
  } ]
};

defs$5.ConnectionStart = 655370;

var methodInfoConnectionStart = defs$5.methodInfoConnectionStart = {
  id: 655370,
  classId: 10,
  methodId: 10,
  name: "ConnectionStart",
  args: [ {
    type: "octet",
    name: "versionMajor",
    default: 0
  }, {
    type: "octet",
    name: "versionMinor",
    default: 9
  }, {
    type: "table",
    name: "serverProperties"
  }, {
    type: "longstr",
    name: "mechanisms",
    default: "PLAIN"
  }, {
    type: "longstr",
    name: "locales",
    default: "en_US"
  } ]
};

defs$5.ConnectionStartOk = 655371;

var methodInfoConnectionStartOk = defs$5.methodInfoConnectionStartOk = {
  id: 655371,
  classId: 10,
  methodId: 11,
  name: "ConnectionStartOk",
  args: [ {
    type: "table",
    name: "clientProperties"
  }, {
    type: "shortstr",
    name: "mechanism",
    default: "PLAIN"
  }, {
    type: "longstr",
    name: "response"
  }, {
    type: "shortstr",
    name: "locale",
    default: "en_US"
  } ]
};

defs$5.ConnectionSecure = 655380;

var methodInfoConnectionSecure = defs$5.methodInfoConnectionSecure = {
  id: 655380,
  classId: 10,
  methodId: 20,
  name: "ConnectionSecure",
  args: [ {
    type: "longstr",
    name: "challenge"
  } ]
};

defs$5.ConnectionSecureOk = 655381;

var methodInfoConnectionSecureOk = defs$5.methodInfoConnectionSecureOk = {
  id: 655381,
  classId: 10,
  methodId: 21,
  name: "ConnectionSecureOk",
  args: [ {
    type: "longstr",
    name: "response"
  } ]
};

defs$5.ConnectionTune = 655390;

var methodInfoConnectionTune = defs$5.methodInfoConnectionTune = {
  id: 655390,
  classId: 10,
  methodId: 30,
  name: "ConnectionTune",
  args: [ {
    type: "short",
    name: "channelMax",
    default: 0
  }, {
    type: "long",
    name: "frameMax",
    default: 0
  }, {
    type: "short",
    name: "heartbeat",
    default: 0
  } ]
};

defs$5.ConnectionTuneOk = 655391;

var methodInfoConnectionTuneOk = defs$5.methodInfoConnectionTuneOk = {
  id: 655391,
  classId: 10,
  methodId: 31,
  name: "ConnectionTuneOk",
  args: [ {
    type: "short",
    name: "channelMax",
    default: 0
  }, {
    type: "long",
    name: "frameMax",
    default: 0
  }, {
    type: "short",
    name: "heartbeat",
    default: 0
  } ]
};

defs$5.ConnectionOpen = 655400;

var methodInfoConnectionOpen = defs$5.methodInfoConnectionOpen = {
  id: 655400,
  classId: 10,
  methodId: 40,
  name: "ConnectionOpen",
  args: [ {
    type: "shortstr",
    name: "virtualHost",
    default: "/"
  }, {
    type: "shortstr",
    name: "capabilities",
    default: ""
  }, {
    type: "bit",
    name: "insist",
    default: !1
  } ]
};

defs$5.ConnectionOpenOk = 655401;

var methodInfoConnectionOpenOk = defs$5.methodInfoConnectionOpenOk = {
  id: 655401,
  classId: 10,
  methodId: 41,
  name: "ConnectionOpenOk",
  args: [ {
    type: "shortstr",
    name: "knownHosts",
    default: ""
  } ]
};

defs$5.ConnectionClose = 655410;

var methodInfoConnectionClose = defs$5.methodInfoConnectionClose = {
  id: 655410,
  classId: 10,
  methodId: 50,
  name: "ConnectionClose",
  args: [ {
    type: "short",
    name: "replyCode"
  }, {
    type: "shortstr",
    name: "replyText",
    default: ""
  }, {
    type: "short",
    name: "classId"
  }, {
    type: "short",
    name: "methodId"
  } ]
};

defs$5.ConnectionCloseOk = 655411;

var methodInfoConnectionCloseOk = defs$5.methodInfoConnectionCloseOk = {
  id: 655411,
  classId: 10,
  methodId: 51,
  name: "ConnectionCloseOk",
  args: []
};

defs$5.ConnectionBlocked = 655420;

var methodInfoConnectionBlocked = defs$5.methodInfoConnectionBlocked = {
  id: 655420,
  classId: 10,
  methodId: 60,
  name: "ConnectionBlocked",
  args: [ {
    type: "shortstr",
    name: "reason",
    default: ""
  } ]
};

defs$5.ConnectionUnblocked = 655421;

var methodInfoConnectionUnblocked = defs$5.methodInfoConnectionUnblocked = {
  id: 655421,
  classId: 10,
  methodId: 61,
  name: "ConnectionUnblocked",
  args: []
};

defs$5.ConnectionUpdateSecret = 655430;

var methodInfoConnectionUpdateSecret = defs$5.methodInfoConnectionUpdateSecret = {
  id: 655430,
  classId: 10,
  methodId: 70,
  name: "ConnectionUpdateSecret",
  args: [ {
    type: "longstr",
    name: "newSecret"
  }, {
    type: "shortstr",
    name: "reason"
  } ]
};

defs$5.ConnectionUpdateSecretOk = 655431;

var methodInfoConnectionUpdateSecretOk = defs$5.methodInfoConnectionUpdateSecretOk = {
  id: 655431,
  classId: 10,
  methodId: 71,
  name: "ConnectionUpdateSecretOk",
  args: []
};

defs$5.ChannelOpen = 1310730;

var methodInfoChannelOpen = defs$5.methodInfoChannelOpen = {
  id: 1310730,
  classId: 20,
  methodId: 10,
  name: "ChannelOpen",
  args: [ {
    type: "shortstr",
    name: "outOfBand",
    default: ""
  } ]
};

defs$5.ChannelOpenOk = 1310731;

var methodInfoChannelOpenOk = defs$5.methodInfoChannelOpenOk = {
  id: 1310731,
  classId: 20,
  methodId: 11,
  name: "ChannelOpenOk",
  args: [ {
    type: "longstr",
    name: "channelId",
    default: ""
  } ]
};

defs$5.ChannelFlow = 1310740;

var methodInfoChannelFlow = defs$5.methodInfoChannelFlow = {
  id: 1310740,
  classId: 20,
  methodId: 20,
  name: "ChannelFlow",
  args: [ {
    type: "bit",
    name: "active"
  } ]
};

defs$5.ChannelFlowOk = 1310741;

var methodInfoChannelFlowOk = defs$5.methodInfoChannelFlowOk = {
  id: 1310741,
  classId: 20,
  methodId: 21,
  name: "ChannelFlowOk",
  args: [ {
    type: "bit",
    name: "active"
  } ]
};

defs$5.ChannelClose = 1310760;

var methodInfoChannelClose = defs$5.methodInfoChannelClose = {
  id: 1310760,
  classId: 20,
  methodId: 40,
  name: "ChannelClose",
  args: [ {
    type: "short",
    name: "replyCode"
  }, {
    type: "shortstr",
    name: "replyText",
    default: ""
  }, {
    type: "short",
    name: "classId"
  }, {
    type: "short",
    name: "methodId"
  } ]
};

defs$5.ChannelCloseOk = 1310761;

var methodInfoChannelCloseOk = defs$5.methodInfoChannelCloseOk = {
  id: 1310761,
  classId: 20,
  methodId: 41,
  name: "ChannelCloseOk",
  args: []
};

defs$5.AccessRequest = 1966090;

var methodInfoAccessRequest = defs$5.methodInfoAccessRequest = {
  id: 1966090,
  classId: 30,
  methodId: 10,
  name: "AccessRequest",
  args: [ {
    type: "shortstr",
    name: "realm",
    default: "/data"
  }, {
    type: "bit",
    name: "exclusive",
    default: !1
  }, {
    type: "bit",
    name: "passive",
    default: !0
  }, {
    type: "bit",
    name: "active",
    default: !0
  }, {
    type: "bit",
    name: "write",
    default: !0
  }, {
    type: "bit",
    name: "read",
    default: !0
  } ]
};

defs$5.AccessRequestOk = 1966091;

var methodInfoAccessRequestOk = defs$5.methodInfoAccessRequestOk = {
  id: 1966091,
  classId: 30,
  methodId: 11,
  name: "AccessRequestOk",
  args: [ {
    type: "short",
    name: "ticket",
    default: 1
  } ]
};

defs$5.ExchangeDeclare = 2621450;

var methodInfoExchangeDeclare = defs$5.methodInfoExchangeDeclare = {
  id: 2621450,
  classId: 40,
  methodId: 10,
  name: "ExchangeDeclare",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "type",
    default: "direct"
  }, {
    type: "bit",
    name: "passive",
    default: !1
  }, {
    type: "bit",
    name: "durable",
    default: !1
  }, {
    type: "bit",
    name: "autoDelete",
    default: !1
  }, {
    type: "bit",
    name: "internal",
    default: !1
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.ExchangeDeclareOk = 2621451;

var methodInfoExchangeDeclareOk = defs$5.methodInfoExchangeDeclareOk = {
  id: 2621451,
  classId: 40,
  methodId: 11,
  name: "ExchangeDeclareOk",
  args: []
};

defs$5.ExchangeDelete = 2621460;

var methodInfoExchangeDelete = defs$5.methodInfoExchangeDelete = {
  id: 2621460,
  classId: 40,
  methodId: 20,
  name: "ExchangeDelete",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "bit",
    name: "ifUnused",
    default: !1
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  } ]
};

defs$5.ExchangeDeleteOk = 2621461;

var methodInfoExchangeDeleteOk = defs$5.methodInfoExchangeDeleteOk = {
  id: 2621461,
  classId: 40,
  methodId: 21,
  name: "ExchangeDeleteOk",
  args: []
};

defs$5.ExchangeBind = 2621470;

var methodInfoExchangeBind = defs$5.methodInfoExchangeBind = {
  id: 2621470,
  classId: 40,
  methodId: 30,
  name: "ExchangeBind",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "destination"
  }, {
    type: "shortstr",
    name: "source"
  }, {
    type: "shortstr",
    name: "routingKey",
    default: ""
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.ExchangeBindOk = 2621471;

var methodInfoExchangeBindOk = defs$5.methodInfoExchangeBindOk = {
  id: 2621471,
  classId: 40,
  methodId: 31,
  name: "ExchangeBindOk",
  args: []
};

defs$5.ExchangeUnbind = 2621480;

var methodInfoExchangeUnbind = defs$5.methodInfoExchangeUnbind = {
  id: 2621480,
  classId: 40,
  methodId: 40,
  name: "ExchangeUnbind",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "destination"
  }, {
    type: "shortstr",
    name: "source"
  }, {
    type: "shortstr",
    name: "routingKey",
    default: ""
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.ExchangeUnbindOk = 2621491;

var methodInfoExchangeUnbindOk = defs$5.methodInfoExchangeUnbindOk = {
  id: 2621491,
  classId: 40,
  methodId: 51,
  name: "ExchangeUnbindOk",
  args: []
};

defs$5.QueueDeclare = 3276810;

var methodInfoQueueDeclare = defs$5.methodInfoQueueDeclare = {
  id: 3276810,
  classId: 50,
  methodId: 10,
  name: "QueueDeclare",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "bit",
    name: "passive",
    default: !1
  }, {
    type: "bit",
    name: "durable",
    default: !1
  }, {
    type: "bit",
    name: "exclusive",
    default: !1
  }, {
    type: "bit",
    name: "autoDelete",
    default: !1
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.QueueDeclareOk = 3276811;

var methodInfoQueueDeclareOk = defs$5.methodInfoQueueDeclareOk = {
  id: 3276811,
  classId: 50,
  methodId: 11,
  name: "QueueDeclareOk",
  args: [ {
    type: "shortstr",
    name: "queue"
  }, {
    type: "long",
    name: "messageCount"
  }, {
    type: "long",
    name: "consumerCount"
  } ]
};

defs$5.QueueBind = 3276820;

var methodInfoQueueBind = defs$5.methodInfoQueueBind = {
  id: 3276820,
  classId: 50,
  methodId: 20,
  name: "QueueBind",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "routingKey",
    default: ""
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.QueueBindOk = 3276821;

var methodInfoQueueBindOk = defs$5.methodInfoQueueBindOk = {
  id: 3276821,
  classId: 50,
  methodId: 21,
  name: "QueueBindOk",
  args: []
};

defs$5.QueuePurge = 3276830;

var methodInfoQueuePurge = defs$5.methodInfoQueuePurge = {
  id: 3276830,
  classId: 50,
  methodId: 30,
  name: "QueuePurge",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  } ]
};

defs$5.QueuePurgeOk = 3276831;

var methodInfoQueuePurgeOk = defs$5.methodInfoQueuePurgeOk = {
  id: 3276831,
  classId: 50,
  methodId: 31,
  name: "QueuePurgeOk",
  args: [ {
    type: "long",
    name: "messageCount"
  } ]
};

defs$5.QueueDelete = 3276840;

var methodInfoQueueDelete = defs$5.methodInfoQueueDelete = {
  id: 3276840,
  classId: 50,
  methodId: 40,
  name: "QueueDelete",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "bit",
    name: "ifUnused",
    default: !1
  }, {
    type: "bit",
    name: "ifEmpty",
    default: !1
  }, {
    type: "bit",
    name: "nowait",
    default: !1
  } ]
};

defs$5.QueueDeleteOk = 3276841;

var methodInfoQueueDeleteOk = defs$5.methodInfoQueueDeleteOk = {
  id: 3276841,
  classId: 50,
  methodId: 41,
  name: "QueueDeleteOk",
  args: [ {
    type: "long",
    name: "messageCount"
  } ]
};

defs$5.QueueUnbind = 3276850;

var methodInfoQueueUnbind = defs$5.methodInfoQueueUnbind = {
  id: 3276850,
  classId: 50,
  methodId: 50,
  name: "QueueUnbind",
  args: [ {
    type: "short",
    name: "ticket",
    default: 0
  }, {
    type: "shortstr",
    name: "queue",
    default: ""
  }, {
    type: "shortstr",
    name: "exchange"
  }, {
    type: "shortstr",
    name: "routingKey",
    default: ""
  }, {
    type: "table",
    name: "arguments",
    default: {}
  } ]
};

defs$5.QueueUnbindOk = 3276851;

var methodInfoQueueUnbindOk = defs$5.methodInfoQueueUnbindOk = {
  id: 3276851,
  classId: 50,
  methodId: 51,
  name: "QueueUnbindOk",
  args: []
};

defs$5.TxSelect = 5898250;

var methodInfoTxSelect = defs$5.methodInfoTxSelect = {
  id: 5898250,
  classId: 90,
  methodId: 10,
  name: "TxSelect",
  args: []
};

defs$5.TxSelectOk = 5898251;

var methodInfoTxSelectOk = defs$5.methodInfoTxSelectOk = {
  id: 5898251,
  classId: 90,
  methodId: 11,
  name: "TxSelectOk",
  args: []
};

defs$5.TxCommit = 5898260;

var methodInfoTxCommit = defs$5.methodInfoTxCommit = {
  id: 5898260,
  classId: 90,
  methodId: 20,
  name: "TxCommit",
  args: []
};

defs$5.TxCommitOk = 5898261;

var methodInfoTxCommitOk = defs$5.methodInfoTxCommitOk = {
  id: 5898261,
  classId: 90,
  methodId: 21,
  name: "TxCommitOk",
  args: []
};

defs$5.TxRollback = 5898270;

var methodInfoTxRollback = defs$5.methodInfoTxRollback = {
  id: 5898270,
  classId: 90,
  methodId: 30,
  name: "TxRollback",
  args: []
};

defs$5.TxRollbackOk = 5898271;

var methodInfoTxRollbackOk = defs$5.methodInfoTxRollbackOk = {
  id: 5898271,
  classId: 90,
  methodId: 31,
  name: "TxRollbackOk",
  args: []
};

defs$5.ConfirmSelect = 5570570;

var methodInfoConfirmSelect = defs$5.methodInfoConfirmSelect = {
  id: 5570570,
  classId: 85,
  methodId: 10,
  name: "ConfirmSelect",
  args: [ {
    type: "bit",
    name: "nowait",
    default: !1
  } ]
};

defs$5.ConfirmSelectOk = 5570571;

var methodInfoConfirmSelectOk = defs$5.methodInfoConfirmSelectOk = {
  id: 5570571,
  classId: 85,
  methodId: 11,
  name: "ConfirmSelectOk",
  args: []
};

defs$5.BasicProperties = 60;

var propertiesInfoBasicProperties = defs$5.propertiesInfoBasicProperties = {
  id: 60,
  name: "BasicProperties",
  args: [ {
    type: "shortstr",
    name: "contentType"
  }, {
    type: "shortstr",
    name: "contentEncoding"
  }, {
    type: "table",
    name: "headers"
  }, {
    type: "octet",
    name: "deliveryMode"
  }, {
    type: "octet",
    name: "priority"
  }, {
    type: "shortstr",
    name: "correlationId"
  }, {
    type: "shortstr",
    name: "replyTo"
  }, {
    type: "shortstr",
    name: "expiration"
  }, {
    type: "shortstr",
    name: "messageId"
  }, {
    type: "timestamp",
    name: "timestamp"
  }, {
    type: "shortstr",
    name: "type"
  }, {
    type: "shortstr",
    name: "userId"
  }, {
    type: "shortstr",
    name: "appId"
  }, {
    type: "shortstr",
    name: "clusterId"
  } ]
};

var frame$1 = {};

const ints = bufferMoreIntsExports;
var defs$4 = defs$5;
var constants$1 = defs$4.constants;
var decode = defs$4.decode;

frame$1.PROTOCOL_HEADER = "AMQP" + String.fromCharCode(0, 0, 9, 1);

/*
  Frame format:

  0      1         3             7                size+7 size+8
  +------+---------+-------------+ +------------+ +-----------+
  | type | channel | size        | | payload    | | frame-end |
  +------+---------+-------------+ +------------+ +-----------+
  octet   short     long            size octets    octet

  In general I want to know those first three things straight away, so I
  can discard frames early.

*/

// framing constants
var FRAME_METHOD = constants$1.FRAME_METHOD,
FRAME_HEARTBEAT = constants$1.FRAME_HEARTBEAT,
FRAME_HEADER = constants$1.FRAME_HEADER,
FRAME_BODY = constants$1.FRAME_BODY,
FRAME_END = constants$1.FRAME_END;

// expected byte sizes for frame parts
const TYPE_BYTES = 1;
const CHANNEL_BYTES = 2;
const SIZE_BYTES = 4;
const FRAME_HEADER_BYTES = TYPE_BYTES + CHANNEL_BYTES + SIZE_BYTES;
const FRAME_END_BYTES = 1;

/**
 * @typedef {{
 *   type: number,
 *   channel: number,
 *   size: number,
 *   payload: Buffer,
 *   rest: Buffer
 * }} FrameStructure
 */

/**
 * This is a polyfill which will read a big int 64 bit as a number.
 * @arg { Buffer } buffer
 * @arg { number } offset
 * @returns { number }
 */
function readInt64BE(buffer, offset) {
  /**
   * We try to use native implementation if available here because
   * buffer-more-ints does not
   */
  if (typeof Buffer.prototype.readBigInt64BE === 'function') {
    return Number(buffer.readBigInt64BE(offset))
  }

  return ints.readInt64BE(buffer, offset)
}

// %%% TESTME possibly better to cons the first bit and write the
// second directly, in the absence of IO lists
/**
 * Make a frame header
 * @arg { number } channel
 * @arg { Buffer } payload
 */
frame$1.makeBodyFrame = function (channel, payload) {
  const frameSize = FRAME_HEADER_BYTES + payload.length + FRAME_END_BYTES;

  const frame = Buffer.alloc(frameSize);

  let offset = 0;

  offset = frame.writeUInt8(FRAME_BODY, offset);
  offset = frame.writeUInt16BE(channel, offset);
  offset = frame.writeInt32BE(payload.length, offset);

  payload.copy(frame, offset);
  offset += payload.length;

  frame.writeUInt8(FRAME_END, offset);

  return frame
};

/**
 * Parse an AMQP frame
 * @arg { Buffer } bin
 * @arg { number } max
 * @returns { FrameStructure | boolean }
 */
function parseFrame$1(bin) {
  if (bin.length < FRAME_HEADER_BYTES) {
    return false
  }

  const type = bin.readUInt8(0);
  const channel = bin.readUInt16BE(1);
  const size = bin.readUInt32BE(3);

  const totalSize = FRAME_HEADER_BYTES + size + FRAME_END_BYTES;

  if (bin.length < totalSize) {
    return false
  }

  const frameEnd = bin.readUInt8(FRAME_HEADER_BYTES + size);

  if (frameEnd !== FRAME_END) {
    throw new Error('Invalid frame')
  }

  return {
    type,
    channel,
    size,
    payload: bin.subarray(FRAME_HEADER_BYTES, FRAME_HEADER_BYTES + size),
    rest: bin.subarray(totalSize)
  }
}

frame$1.parseFrame = parseFrame$1;

var HEARTBEAT$2 = {channel: 0};

/**
 * Decode AMQP frame into JS object
 * @param { FrameStructure } frame
 * @returns
 */
frame$1.decodeFrame = (frame) => {
  const payload = frame.payload;
  const channel = frame.channel;

  switch (frame.type) {
    case FRAME_METHOD: {
      const id = payload.readUInt32BE(0);
      const args = payload.subarray(4);
      const fields = decode(id, args);
      return { id, channel, fields }
    }
    case FRAME_HEADER: {
      const id = payload.readUInt16BE(0);
      // const weight = payload.readUInt16BE(2)
      const size = readInt64BE(payload, 4);
      const flagsAndfields = payload.subarray(12);
      const fields = decode(id, flagsAndfields);
      return { id, channel, size, fields }
    }
    case FRAME_BODY:
      return { channel, content: payload }
    case FRAME_HEARTBEAT:
      return HEARTBEAT$2
    default:
      throw new Error('Unknown frame type ' + frame.type)
  }
};

// encoded heartbeat
frame$1.HEARTBEAT_BUF = Buffer.from([constants$1.FRAME_HEARTBEAT,
                                           0, 0, 0, 0, // size = 0
                                           0, 0, // channel = 0
                                           constants$1.FRAME_END]);

frame$1.HEARTBEAT = HEARTBEAT$2;

var mux = {};

// A Mux is an object into which other readable streams may be piped;
// it then writes 'packets' from the upstreams to the given
// downstream.

var assert$1 = require$$0;

var schedule = (typeof setImmediate === 'function') ?
  setImmediate : process.nextTick;

let Mux$1 = class Mux {
  constructor (downstream) {
    this.newStreams = [];
    this.oldStreams = [];
    this.blocked = false;
    this.scheduledRead = false;

    this.out = downstream;
    var self = this;
    downstream.on('drain', function () {
      self.blocked = false;
      self._readIncoming();
    });
  }

  // There are 2 states we can be in:
  // - waiting for outbound capacity, which will be signalled by a
  // - 'drain' event on the downstream; or,
  // - no packets to send, waiting for an inbound buffer to have
  //   packets, which will be signalled by a 'readable' event
  // If we write all packets available whenever there is outbound
  // capacity, we will either run out of outbound capacity (`#write`
  // returns false), or run out of packets (all calls to an
  // `inbound.read()` have returned null).
  _readIncoming () {

    // We may be sent here speculatively, if an incoming stream has
    // become readable
    if (this.blocked) return;

    var accepting = true;
    var out = this.out;

    // Try to read a chunk from each stream in turn, until all streams
    // are empty, or we exhaust our ability to accept chunks.
    function roundrobin (streams) {
      var s;
      while (accepting && (s = streams.shift())) {
        var chunk = s.read();
        if (chunk !== null) {
          accepting = out.write(chunk);
          streams.push(s);
        }
      }
    }

    roundrobin(this.newStreams);

    // Either we exhausted the new queues, or we ran out of capacity. If
    // we ran out of capacity, all the remaining new streams (i.e.,
    // those with packets left) become old streams. This effectively
    // prioritises streams that keep their buffers close to empty over
    // those that are constantly near full.
    if (accepting) { // all new queues are exhausted, write as many as
      // we can from the old streams
      assert$1.equal(0, this.newStreams.length);
      roundrobin(this.oldStreams);
    }
    else { // ran out of room
      assert$1(this.newStreams.length > 0, "Expect some new streams to remain");
      Array.prototype.push.apply(this.oldStreams, this.newStreams);
      this.newStreams = [];
    }
    // We may have exhausted all the old queues, or run out of room;
    // either way, all we need to do is record whether we have capacity
    // or not, so any speculative reads will know
    this.blocked = !accepting;
  }

  _scheduleRead () {
    var self = this;

    if (!self.scheduledRead) {
      schedule(function () {
        self.scheduledRead = false;
        self._readIncoming();
      });
      self.scheduledRead = true;
    }
  }

  pipeFrom (readable) {
    var self = this;

    function enqueue () {
      self.newStreams.push(readable);
      self._scheduleRead();
    }

    function cleanup () {
      readable.removeListener('readable', enqueue);
      readable.removeListener('error', cleanup);
      readable.removeListener('end', cleanup);
      readable.removeListener('unpipeFrom', cleanupIfMe);
    }
    function cleanupIfMe (dest) {
      if (dest === self) cleanup();
    }

    readable.on('unpipeFrom', cleanupIfMe);
    readable.on('end', cleanup);
    readable.on('error', cleanup);
    readable.on('readable', enqueue);
  }

  unpipeFrom (readable) {
    readable.emit('unpipeFrom', this);
  }
};

mux.Mux = Mux$1;

var heartbeat = {exports: {}};

(function (module) {

	var EventEmitter = require$$0$1;

	// Exported so that we can mess with it in tests
	module.exports.UNITS_TO_MS = 1000;

	class Heart extends EventEmitter {
	  constructor (interval, checkSend, checkRecv) {
	    super();

	    this.interval = interval;

	    var intervalMs = interval * module.exports.UNITS_TO_MS;
	    // Function#bind is my new best friend
	    var beat = this.emit.bind(this, 'beat');
	    var timeout = this.emit.bind(this, 'timeout');

	    this.sendTimer = setInterval(
	      this.runHeartbeat.bind(this, checkSend, beat), intervalMs / 2);

	    // A timeout occurs if I see nothing for *two consecutive* intervals
	    var recvMissed = 0;
	    function missedTwo () {
	      if (!checkRecv())
	        return (++recvMissed < 2);
	      else { recvMissed = 0; return true; }
	    }
	    this.recvTimer = setInterval(
	      this.runHeartbeat.bind(this, missedTwo, timeout), intervalMs);
	  }

	  clear () {
	    clearInterval(this.sendTimer);
	    clearInterval(this.recvTimer);
	  }

	  runHeartbeat (check, fail) {
	    // Have we seen activity?
	    if (!check())
	      fail();
	  }
	}

	module.exports.Heart = Heart; 
} (heartbeat));

var heartbeatExports = heartbeat.exports;

var format$1 = {};

var defs$3 = defs$5;
var format = require$$1.format;
var HEARTBEAT$1 = frame$1.HEARTBEAT;

format$1.closeMessage = function(close) {
  var code = close.fields.replyCode;
  return format('%d (%s) with message "%s"',
                code, defs$3.constant_strs[code],
                close.fields.replyText);
};

format$1.methodName = function(id) {
  return defs$3.info(id).name;
};

format$1.inspect = function(frame, showFields) {
  if (frame === HEARTBEAT$1) {
    return '<Heartbeat>';
  }
  else if (!frame.id) {
    return format('<Content channel:%d size:%d>',
                  frame.channel, frame.size);
  }
  else {
    var info = defs$3.info(frame.id);
    return format('<%s channel:%d%s>', info.name, frame.channel,
                  (showFields)
                  ? ' ' + JSON.stringify(frame.fields, undefined, 2)
                  : '');
  }
};

var bitset = {};

/**
 * A bitset implementation, after that in java.util.  Yes there
 * already exist such things, but none implement next{Clear|Set}Bit or
 * equivalent, and none involved me tooling about for an evening.
 */
let BitSet$1 = class BitSet {
  /**
   * @param {number} [size]
   */
  constructor(size) {
    if (size) {
      const numWords = Math.ceil(size / 32);
      this.words = new Array(numWords);
    }
    else {
      this.words = [];
    }
    this.wordsInUse = 0; // = number, not index
  }

  /**
   * @param {number} numWords
   */
  ensureSize(numWords) {
    const wordsPresent = this.words.length;
    if (wordsPresent < numWords) {
      this.words = this.words.concat(new Array(numWords - wordsPresent));
    }
  }

  /**
   * @param {number} bitIndex
   */
  set(bitIndex) {
    const w = wordIndex(bitIndex);
    if (w >= this.wordsInUse) {
      this.ensureSize(w + 1);
      this.wordsInUse = w + 1;
    }
    const bit = 1 << bitIndex;
    this.words[w] |= bit;
  }

  /**
   * @param {number} bitIndex
   */
  clear(bitIndex) {
    const w = wordIndex(bitIndex);
    if (w >= this.wordsInUse) return;
    const mask = ~(1 << bitIndex);
    this.words[w] &= mask;
  }

  /**
   * @param {number} bitIndex
   */
  get(bitIndex) {
    const w = wordIndex(bitIndex);
    if (w >= this.wordsInUse) return false; // >= since index vs size
    const bit = 1 << bitIndex;
    return !!(this.words[w] & bit);
  }

  /**
   * Give the next bit that is set on or after fromIndex, or -1 if no such bit
   *
   * @param {number} fromIndex
   */
  nextSetBit(fromIndex) {
    let w = wordIndex(fromIndex);
    if (w >= this.wordsInUse) return -1;

    // the right-hand side is shifted to only test the bits of the first
    // word that are > fromIndex
    let word = this.words[w] & (0xffffffff << fromIndex);
    while (true) {
      if (word) return (w * 32) + trailingZeros(word);
      w++;
      if (w === this.wordsInUse) return -1;
      word = this.words[w];
    }
  }

  /**
   * @param {number} fromIndex
   */
  nextClearBit(fromIndex) {
    let w = wordIndex(fromIndex);
    if (w >= this.wordsInUse) return fromIndex;

    let word = ~(this.words[w]) & (0xffffffff << fromIndex);
    while (true) {
      if (word) return (w * 32) + trailingZeros(word);
      w++;
      if (w == this.wordsInUse) return w * 32;
      word = ~(this.words[w]);
    }
  }
};

/**
 * @param {number} bitIndex
 */
function wordIndex(bitIndex) {
  return Math.floor(bitIndex / 32);
}

/**
 * @param {number} i
 */
function trailingZeros(i) {
  // From Hacker's Delight, via JDK. Probably far less effective here,
  // since bit ops are not necessarily the quick way to do things in
  // JS.
  if (i === 0) return 32;
  let y, n = 31;
  y = i << 16; if (y != 0) { n = n -16; i = y; }
  y = i << 8;  if (y != 0) { n = n - 8; i = y; }
  y = i << 4;  if (y != 0) { n = n - 4; i = y; }
  y = i << 2;  if (y != 0) { n = n - 2; i = y; }
  return n - ((i << 1) >>> 31);
}

bitset.BitSet = BitSet$1;

var error = {};

var inherits = require$$1.inherits;

function trimStack(stack, num) {
  return stack && stack.split('\n').slice(num).join('\n');
}

function IllegalOperationError$2(msg, stack) {
  var tmp = new Error();
  this.message = msg;
  this.stack = this.toString() + '\n' + trimStack(tmp.stack, 2);
  this.stackAtStateChange = stack;
}
inherits(IllegalOperationError$2, Error);

IllegalOperationError$2.prototype.name = 'IllegalOperationError';

function stackCapture$2(reason) {
  var e = new Error();
  return 'Stack capture: ' + reason + '\n' +
    trimStack(e.stack, 2);
}

error.IllegalOperationError = IllegalOperationError$2;
error.stackCapture = stackCapture$2;

var defs$2 = defs$5;
var constants = defs$2.constants;
var frame = frame$1;
var HEARTBEAT = frame.HEARTBEAT;
var Mux = mux.Mux;

var Duplex = require$$3.Duplex;
var EventEmitter$2 = require$$0$1;
var Heart = heartbeatExports.Heart;

var methodName$1 = format$1.methodName;
var closeMsg$1 = format$1.closeMessage;
var inspect$2 = format$1.inspect;

var BitSet = bitset.BitSet;
var fmt$2 = require$$1.format;
var PassThrough = require$$3.PassThrough;
var IllegalOperationError$1 = error.IllegalOperationError;
var stackCapture$1 = error.stackCapture;

// High-water mark for channel write buffers, in 'objects' (which are
// encoded frames as buffers).
var DEFAULT_WRITE_HWM = 1024;
// If all the frames of a message (method, properties, content) total
// to less than this, copy them into a single buffer and write it all
// at once. Note that this is less than the minimum frame size: if it
// was greater, we might have to fragment the content.
var SINGLE_CHUNK_THRESHOLD = 2048;

let Connection$1 = class Connection extends EventEmitter$2 {
  constructor (underlying) {
    super();

    var stream = this.stream = wrapStream(underlying);
    this.muxer = new Mux(stream);

    // frames
    this.rest = Buffer.alloc(0);
    this.frameMax = constants.FRAME_MIN_SIZE;
    this.sentSinceLastCheck = false;
    this.recvSinceLastCheck = false;

    this.expectSocketClose = false;
    this.freeChannels = new BitSet();
    this.channels = [{
      channel: { accept: channel0(this) },
      buffer: underlying
    }];
  }

  // This changed between versions, as did the codec, methods, etc. AMQP
  // 0-9-1 is fairly similar to 0.8, but better, and nothing implements
  // 0.8 that doesn't implement 0-9-1. In other words, it doesn't make
  // much sense to generalise here.
  sendProtocolHeader () {
    this.sendBytes(frame.PROTOCOL_HEADER);
  }

  /*
    The frighteningly complicated opening protocol (spec section 2.2.4):

       Client -> Server

         protocol header ->
           <- start
         start-ok ->
       .. next two zero or more times ..
           <- secure
         secure-ok ->
           <- tune
         tune-ok ->
         open ->
           <- open-ok

  If I'm only supporting SASL's PLAIN mechanism (which I am for the time
  being), it gets a bit easier since the server won't in general send
  back a `secure`, it'll just send `tune` after the `start-ok`.
  (SASL PLAIN: http://tools.ietf.org/html/rfc4616)

  */
  open (allFields, openCallback0) {
    var self = this;
    var openCallback = openCallback0 || function () { };

    // This is where we'll put our negotiated values
    var tunedOptions = Object.create(allFields);

    function wait (k) {
      self.step(function (err, frame) {
        if (err !== null)
          bail(err);
        else if (frame.channel !== 0) {
          bail(new Error(
            fmt$2("Frame on channel != 0 during handshake: %s",
              inspect$2(frame, false))));
        }
        else
          k(frame);
      });
    }

    function expect (Method, k) {
      wait(function (frame) {
        if (frame.id === Method)
          k(frame);
        else {
          bail(new Error(
            fmt$2("Expected %s; got %s",
              methodName$1(Method), inspect$2(frame, false))));
        }
      });
    }

    function bail (err) {
      openCallback(err);
    }

    function send (Method) {
      // This can throw an exception if there's some problem with the
      // options; e.g., something is a string instead of a number.
      self.sendMethod(0, Method, tunedOptions);
    }

    function negotiate (server, desired) {
      // We get sent values for channelMax, frameMax and heartbeat,
      // which we may accept or lower (subject to a minimum for
      // frameMax, but we'll leave that to the server to enforce). In
      // all cases, `0` really means "no limit", or rather the highest
      // value in the encoding, e.g., unsigned short for channelMax.
      if (server === 0 || desired === 0) {
        // i.e., whichever places a limit, if either
        return Math.max(server, desired);
      }
      else {
        return Math.min(server, desired);
      }
    }

    function onStart (start) {
      var mechanisms = start.fields.mechanisms.toString().split(' ');
      if (mechanisms.indexOf(allFields.mechanism) < 0) {
        bail(new Error(fmt$2('SASL mechanism %s is not provided by the server',
          allFields.mechanism)));
        return;
      }
      self.serverProperties = start.fields.serverProperties;
      try {
        send(defs$2.ConnectionStartOk);
      } catch (err) {
        bail(err);
        return;
      }
      wait(afterStartOk);
    }

    function afterStartOk (reply) {
      switch (reply.id) {
        case defs$2.ConnectionSecure:
          bail(new Error(
            "Wasn't expecting to have to go through secure"));
          break;
        case defs$2.ConnectionClose:
          bail(new Error(fmt$2("Handshake terminated by server: %s",
            closeMsg$1(reply))));
          break;
        case defs$2.ConnectionTune:
          var fields = reply.fields;
          tunedOptions.frameMax =
            negotiate(fields.frameMax, allFields.frameMax);
          tunedOptions.channelMax =
            negotiate(fields.channelMax, allFields.channelMax);
          tunedOptions.heartbeat =
            negotiate(fields.heartbeat, allFields.heartbeat);
          try {
            send(defs$2.ConnectionTuneOk);
            send(defs$2.ConnectionOpen);
          } catch (err) {
            bail(err);
            return;
          }
          expect(defs$2.ConnectionOpenOk, onOpenOk);
          break;
        default:
          bail(new Error(
            fmt$2("Expected connection.secure, connection.close, " +
              "or connection.tune during handshake; got %s",
              inspect$2(reply, false))));
          break;
      }
    }

    function onOpenOk (openOk) {
      // Impose the maximum of the encoded value, if the negotiated
      // value is zero, meaning "no, no limits"
      self.channelMax = tunedOptions.channelMax || 0xffff;
      self.frameMax = tunedOptions.frameMax || 0xffffffff;
      // 0 means "no heartbeat", rather than "maximum period of
      // heartbeating"
      self.heartbeat = tunedOptions.heartbeat;
      self.heartbeater = self.startHeartbeater();
      self.accept = mainAccept;
      succeed(openOk);
    }

    // If the server closes the connection, it's probably because of
    // something we did
    function endWhileOpening (err) {
      bail(err || new Error('Socket closed abruptly ' +
        'during opening handshake'));
    }

    this.stream.on('end', endWhileOpening);
    this.stream.on('error', endWhileOpening);

    function succeed (ok) {
      self.stream.removeListener('end', endWhileOpening);
      self.stream.removeListener('error', endWhileOpening);
      self.stream.on('error', self.onSocketError.bind(self));
      self.stream.on('end', self.onSocketError.bind(
        self, new Error('Unexpected close')));
      self.on('frameError', self.onSocketError.bind(self));
      self.acceptLoop();
      openCallback(null, ok);
    }

    // Now kick off the handshake by prompting the server
    this.sendProtocolHeader();
    expect(defs$2.ConnectionStart, onStart);
  }

  // Closing things: AMQP has a closing handshake that applies to
  // closing both connects and channels. As the initiating party, I send
  // Close, then ignore all frames until I see either CloseOK --
  // which signifies that the other party has seen the Close and shut
  // the connection or channel down, so it's fine to free resources; or
  // Close, which means the other party also wanted to close the
  // whatever, and I should send CloseOk so it can free resources,
  // then go back to waiting for the CloseOk. If I receive a Close
  // out of the blue, I should throw away any unsent frames (they will
  // be ignored anyway) and send CloseOk, then clean up resources. In
  // general, Close out of the blue signals an error (or a forced
  // closure, which may as well be an error).
  //
  //  RUNNING [1] --- send Close ---> Closing [2] ---> recv Close --+
  //     |                               |                         [3]
  //     |                               +------ send CloseOk ------+
  //  recv Close                   recv CloseOk
  //     |                               |
  //     V                               V
  //  Ended [4] ---- send CloseOk ---> Closed [5]
  //
  // [1] All frames accepted; getting a Close frame from the server
  // moves to Ended; client may initiate a close by sending Close
  // itself.
  // [2] Client has initiated a close; only CloseOk or (simulataneously
  // sent) Close is accepted.
  // [3] Simultaneous close
  // [4] Server won't send any more frames; accept no more frames, send
  // CloseOk.
  // [5] Fully closed, client will send no more, server will send no
  // more. Signal 'close' or 'error'.
  //
  // There are two signalling mechanisms used in the API. The first is
  // that calling `close` will return a promise, that will either
  // resolve once the connection or channel is cleanly shut down, or
  // will reject if the shutdown times out.
  //
  // The second is the 'close' and 'error' events. These are
  // emitted as above. The events will fire *before* promises are
  // resolved.
  // Close the connection without even giving a reason. Typical.
  close (closeCallback) {
    var k = closeCallback && function () { closeCallback(null); };
    this.closeBecause("Cheers, thanks", constants.REPLY_SUCCESS, k);
  }

  // Close with a reason and a 'code'. I'm pretty sure RabbitMQ totally
  // ignores these; maybe it logs them. The continuation will be invoked
  // when the CloseOk has been received, and before the 'close' event.
  closeBecause (reason, code, k) {
    this.sendMethod(0, defs$2.ConnectionClose, {
      replyText: reason,
      replyCode: code,
      methodId: 0, classId: 0
    });
    var s = stackCapture$1('closeBecause called: ' + reason);
    this.toClosing(s, k);
  }

  closeWithError (reason, code, error) {
    this.emit('error', error);
    this.closeBecause(reason, code);
  }

  onSocketError (err) {
    if (!this.expectSocketClose) {
      // forestall any more calls to onSocketError, since we're signed
      // up for `'error'` *and* `'end'`
      this.expectSocketClose = true;
      this.emit('error', err);
      var s = stackCapture$1('Socket error');
      this.toClosed(s, err);
    }
  }

  // A close has been initiated. Repeat: a close has been initiated.
  // This means we should not send more frames, anyway they will be
  // ignored. We also have to shut down all the channels.
  toClosing (capturedStack, k) {
    var send = this.sendMethod.bind(this);

    this.accept = function (f) {
      if (f.id === defs$2.ConnectionCloseOk) {
        if (k)
          k();
        var s = stackCapture$1('ConnectionCloseOk received');
        this.toClosed(s, undefined);
      }
      else if (f.id === defs$2.ConnectionClose) {
        send(0, defs$2.ConnectionCloseOk, {});
      }
      // else ignore frame
    };
    invalidateSend$1(this, 'Connection closing', capturedStack);
  }

  _closeChannels (capturedStack) {
    for (var i = 1; i < this.channels.length; i++) {
      var ch = this.channels[i];
      if (ch !== null) {
        ch.channel.toClosed(capturedStack); // %%% or with an error? not clear
      }
    }
  }

  // A close has been confirmed. Cease all communication.
  toClosed (capturedStack, maybeErr) {
    this._closeChannels(capturedStack);
    var info = fmt$2('Connection closed (%s)',
      (maybeErr) ? maybeErr.toString() : 'by client');
    // Tidy up, invalidate enverything, dynamite the bridges.
    invalidateSend$1(this, info, capturedStack);
    this.accept = invalidOp$1(info, capturedStack);
    this.close = function (cb) {
      cb && cb(new IllegalOperationError$1(info, capturedStack));
    };
    if (this.heartbeater)
      this.heartbeater.clear();
    // This is certainly true now, if it wasn't before
    this.expectSocketClose = true;
    this.stream.end();
    this.emit('close', maybeErr);
  }

  _updateSecret(newSecret, reason, cb) {
    this.sendMethod(0, defs$2.ConnectionUpdateSecret, {
      newSecret,
      reason
    });
    this.once('update-secret-ok', cb);
  }

  // ===
  startHeartbeater () {
    if (this.heartbeat === 0)
      return null;
    else {
      var self = this;
      var hb = new Heart(this.heartbeat,
        this.checkSend.bind(this),
        this.checkRecv.bind(this));
      hb.on('timeout', function () {
        var hberr = new Error("Heartbeat timeout");
        self.emit('error', hberr);
        var s = stackCapture$1('Heartbeat timeout');
        self.toClosed(s, hberr);
      });
      hb.on('beat', function () {
        self.sendHeartbeat();
      });
      return hb;
    }
  }

  // I use an array to keep track of the channels, rather than an
  // object. The channel identifiers are numbers, and allocated by the
  // connection. If I try to allocate low numbers when they are
  // available (which I do, by looking from the start of the bitset),
  // this ought to keep the array small, and out of 'sparse array
  // storage'. I also set entries to null, rather than deleting them, in
  // the expectation that the next channel allocation will fill the slot
  // again rather than growing the array. See
  // http://www.html5rocks.com/en/tutorials/speed/v8/
  freshChannel (channel, options) {
    var next = this.freeChannels.nextClearBit(1);
    if (next < 0 || next > this.channelMax)
      throw new Error("No channels left to allocate");
    this.freeChannels.set(next);

    var hwm = (options && options.highWaterMark) || DEFAULT_WRITE_HWM;
    var writeBuffer = new PassThrough({
      objectMode: true, highWaterMark: hwm
    });
    this.channels[next] = { channel: channel, buffer: writeBuffer };
    writeBuffer.on('drain', function () {
      channel.onBufferDrain();
    });
    this.muxer.pipeFrom(writeBuffer);
    return next;
  }

  releaseChannel (channel) {
    this.freeChannels.clear(channel);
    var buffer = this.channels[channel].buffer;
    buffer.end(); // will also cause it to be unpiped
    this.channels[channel] = null;
  }

  acceptLoop () {
    var self = this;

    function go () {
      try {
        var f; while (f = self.recvFrame())
          self.accept(f);
      }
      catch (e) {
        self.emit('frameError', e);
      }
    }
    self.stream.on('readable', go);
    go();
  }

  step (cb) {
    var self = this;
    function recv () {
      var f;
      try {
        f = self.recvFrame();
      }
      catch (e) {
        cb(e, null);
        return;
      }
      if (f)
        cb(null, f);
      else
        self.stream.once('readable', recv);
    }
    recv();
  }

  checkSend () {
    var check = this.sentSinceLastCheck;
    this.sentSinceLastCheck = false;
    return check;
  }

  checkRecv () {
    var check = this.recvSinceLastCheck;
    this.recvSinceLastCheck = false;
    return check;
  }

  sendBytes (bytes) {
    this.sentSinceLastCheck = true;
    this.stream.write(bytes);
  }

  sendHeartbeat () {
    return this.sendBytes(frame.HEARTBEAT_BUF);
  }

  sendMethod (channel, Method, fields) {
    var frame = encodeMethod(Method, channel, fields);
    this.sentSinceLastCheck = true;
    var buffer = this.channels[channel].buffer;
    return buffer.write(frame);
  }

  sendMessage (channel, Method, fields, Properties, props, content) {
    if (!Buffer.isBuffer(content))
      throw new TypeError('content is not a buffer');

    var mframe = encodeMethod(Method, channel, fields);
    var pframe = encodeProperties(Properties, channel,
      content.length, props);
    var buffer = this.channels[channel].buffer;
    this.sentSinceLastCheck = true;

    var methodHeaderLen = mframe.length + pframe.length;
    var bodyLen = (content.length > 0) ?
      content.length + FRAME_OVERHEAD : 0;
    var allLen = methodHeaderLen + bodyLen;

    if (allLen < SINGLE_CHUNK_THRESHOLD) {
      // Use `allocUnsafe` to avoid excessive allocations and CPU usage
      // from zeroing. The returned Buffer is not zeroed and so must be
      // completely filled to be used safely.
      // See https://github.com/amqp-node/amqplib/pull/695
      var all = Buffer.allocUnsafe(allLen);
      var offset = mframe.copy(all, 0);
      offset += pframe.copy(all, offset);

      if (bodyLen > 0)
        makeBodyFrame(channel, content).copy(all, offset);
      return buffer.write(all);
    }
    else {
      if (methodHeaderLen < SINGLE_CHUNK_THRESHOLD) {
        // Use `allocUnsafe` to avoid excessive allocations and CPU usage
        // from zeroing. The returned Buffer is not zeroed and so must be
        // completely filled to be used safely.
        // See https://github.com/amqp-node/amqplib/pull/695
        var both = Buffer.allocUnsafe(methodHeaderLen);
        var offset = mframe.copy(both, 0);
        pframe.copy(both, offset);
        buffer.write(both);
      }
      else {
        buffer.write(mframe);
        buffer.write(pframe);
      }
      return this.sendContent(channel, content);
    }
  }

  sendContent (channel, body) {
    if (!Buffer.isBuffer(body)) {
      throw new TypeError(fmt$2("Expected buffer; got %s", body));
    }
    var writeResult = true;
    var buffer = this.channels[channel].buffer;

    var maxBody = this.frameMax - FRAME_OVERHEAD;

    for (var offset = 0; offset < body.length; offset += maxBody) {
      var end = offset + maxBody;
      var slice = (end > body.length) ? body.subarray(offset) : body.subarray(offset, end);
      var bodyFrame = makeBodyFrame(channel, slice);
      writeResult = buffer.write(bodyFrame);
    }
    this.sentSinceLastCheck = true;
    return writeResult;
  }

  recvFrame () {
    // %%% identifying invariants might help here?
    var frame = parseFrame(this.rest);

    if (!frame) {
      var incoming = this.stream.read();
      if (incoming === null) {
        return false;
      }
      else {
        this.recvSinceLastCheck = true;
        this.rest = Buffer.concat([this.rest, incoming]);
        return this.recvFrame();
      }
    }
    else {
      this.rest = frame.rest;
      return decodeFrame(frame);
    }
  }
};

// Usual frame accept mode
function mainAccept(frame) {
  var rec = this.channels[frame.channel];
  if (rec) { return rec.channel.accept(frame); }
  // NB CHANNEL_ERROR may not be right, but I don't know what is ..
  else
    this.closeWithError(
      fmt$2('Frame on unknown channel %d', frame.channel),
      constants.CHANNEL_ERROR,
      new Error(fmt$2("Frame on unknown channel: %s",
                    inspect$2(frame, false))));
}

// Handle anything that comes through on channel 0, that's the
// connection control channel. This is only used once mainAccept is
// installed as the frame handler, after the opening handshake.
function channel0(connection) {
  return function(f) {
    // Once we get a 'close', we know 1. we'll get no more frames, and
    // 2. anything we send except close, or close-ok, will be
    // ignored. If we already sent 'close', this won't be invoked since
    // we're already in closing mode; if we didn't well we're not going
    // to send it now are we.
    if (f === HEARTBEAT); // ignore; it's already counted as activity
                          // on the socket, which is its purpose
    else if (f.id === defs$2.ConnectionClose) {
      // Oh. OK. I guess we're done here then.
      connection.sendMethod(0, defs$2.ConnectionCloseOk, {});
      var emsg = fmt$2('Connection closed: %s', closeMsg$1(f));
      var s = stackCapture$1(emsg);
      var e = new Error(emsg);
      e.code = f.fields.replyCode;
      if (isFatalError(e)) {
        connection.emit('error', e);
      }
      connection.toClosed(s, e);
    }
    else if (f.id === defs$2.ConnectionBlocked) {
      connection.emit('blocked', f.fields.reason);
    }
    else if (f.id === defs$2.ConnectionUnblocked) {
      connection.emit('unblocked');
    }
    else if (f.id === defs$2.ConnectionUpdateSecretOk) {
      connection.emit('update-secret-ok');
    }
    else {
      connection.closeWithError(
        fmt$2("Unexpected frame on channel 0"),
        constants.UNEXPECTED_FRAME,
        new Error(fmt$2("Unexpected frame on channel 0: %s",
                      inspect$2(f, false))));
    }
  };
}

function invalidOp$1(msg, stack) {
  return function() {
    throw new IllegalOperationError$1(msg, stack);
  };
}

function invalidateSend$1(conn, msg, stack) {
  conn.sendMethod = conn.sendContent = conn.sendMessage =
    invalidOp$1(msg, stack);
}

var encodeMethod = defs$2.encodeMethod;
var encodeProperties = defs$2.encodeProperties;

var FRAME_OVERHEAD = defs$2.FRAME_OVERHEAD;
var makeBodyFrame = frame.makeBodyFrame;

var parseFrame = frame.parseFrame;
var decodeFrame = frame.decodeFrame;

function wrapStream(s) {
  if (s instanceof Duplex) return s;
  else {
    var ws = new Duplex();
    ws.wrap(s); //wraps the readable side of things
    ws._write = function(chunk, encoding, callback) {
      return s.write(chunk, encoding, callback);
    };
    return ws;
  }
}

function isFatalError(error) {
  switch (error && error.code) {
  case defs$2.constants.CONNECTION_FORCED:
  case defs$2.constants.REPLY_SUCCESS:
    return false;
  default:
    return true;
  }
}

connection.Connection = Connection$1;
connection.isFatalError = isFatalError;

var credentials$1 = {};

//
//
//

// Different kind of credentials that can be supplied when opening a
// connection, corresponding to SASL mechanisms There's only two
// useful mechanisms that RabbitMQ implements:
//  * PLAIN (send username and password in the plain)
//  * EXTERNAL (assume the server will figure out who you are from
//    context, i.e., your SSL certificate)
var codec = codec$2;

credentials$1.plain = function(user, passwd) {
  return {
    mechanism: 'PLAIN',
    response: function() {
      return Buffer.from(['', user, passwd].join(String.fromCharCode(0)))
    },
    username: user,
    password: passwd
  }
};

credentials$1.amqplain = function(user, passwd) {
  return {
    mechanism: 'AMQPLAIN',
    response: function() {
      const buffer = Buffer.alloc(16384);
      const size = codec.encodeTable(buffer, { LOGIN: user, PASSWORD: passwd}, 0);
      return buffer.subarray(4, size);
    },
    username: user,
    password: passwd
  }
};

credentials$1.external = function() {
  return {
    mechanism: 'EXTERNAL',
    response: function() { return Buffer.from(''); }
  }
};

var name = "amqplib";
var homepage = "http://amqp-node.github.io/amqplib/";
var main = "./channel_api.js";
var version = "0.10.8";
var description = "An AMQP 0-9-1 (e.g., RabbitMQ) library and client.";
var repository = {
	type: "git",
	url: "git+https://github.com/amqp-node/amqplib.git"
};
var engines = {
	node: ">=10"
};
var dependencies = {
	"buffer-more-ints": "~1.0.0",
	"url-parse": "~1.5.10"
};
var devDependencies = {
	claire: "0.4.1",
	mocha: "^9.2.2",
	nyc: "^15.1.0",
	"uglify-js": "2.8.x"
};
var scripts = {
	test: "make test"
};
var keywords = [
	"AMQP",
	"AMQP 0-9-1",
	"RabbitMQ"
];
var author = "Michael Bridgen <mikeb@squaremobius.net>";
var license = "MIT";
var require$$5 = {
	name: name,
	homepage: homepage,
	main: main,
	version: version,
	description: description,
	repository: repository,
	engines: engines,
	dependencies: dependencies,
	devDependencies: devDependencies,
	scripts: scripts,
	keywords: keywords,
	author: author,
	license: license
};

var URL = urlParse;
var QS = require$$1$1;
var Connection = connection.Connection;
var fmt$1 = require$$1.format;
var credentials = credentials$1;

function copyInto(obj, target) {
  var keys = Object.keys(obj);
  var i = keys.length;
  while (i--) {
    var k = keys[i];
    target[k] = obj[k];
  }
  return target;
}

// Adapted from util._extend, which is too fringe to use.
function clone(obj) {
  return copyInto(obj, {});
}

var CLIENT_PROPERTIES = {
  "product": "amqplib",
  "version": require$$5.version,
  "platform": fmt$1('Node.JS %s', process.version),
  "information": "https://amqp-node.github.io/amqplib/",
  "capabilities": {
    "publisher_confirms": true,
    "exchange_exchange_bindings": true,
    "basic.nack": true,
    "consumer_cancel_notify": true,
    "connection.blocked": true,
    "authentication_failure_close": true
  }
};

// Construct the main frames used in the opening handshake
function openFrames(vhost, query, credentials, extraClientProperties) {
  if (!vhost)
    vhost = '/';
  else
    vhost = QS.unescape(vhost);

  var query = query || {};

  function intOrDefault(val, def) {
    return (val === undefined) ? def : parseInt(val);
  }

  var clientProperties = Object.create(CLIENT_PROPERTIES);

  return {
    // start-ok
    'clientProperties': copyInto(extraClientProperties, clientProperties),
    'mechanism': credentials.mechanism,
    'response': credentials.response(),
    'locale': query.locale || 'en_US',

    // tune-ok
    'channelMax': intOrDefault(query.channelMax, 0),
    'frameMax': intOrDefault(query.frameMax, 131072),
    'heartbeat': intOrDefault(query.heartbeat, 0),

    // open
    'virtualHost': vhost,
    'capabilities': '',
    'insist': 0
  };
}

// Decide on credentials based on what we're supplied.
function credentialsFromUrl(parts) {
  var user = 'guest', passwd = 'guest';
  if (parts.username != '' || parts.password != '') {
    user = (parts.username) ? unescape(parts.username) : '';
    passwd = (parts.password) ? unescape(parts.password) : '';
  }
  return credentials.plain(user, passwd);
}

function connect$1(url, socketOptions, openCallback) {
  // tls.connect uses `util._extend()` on the options given it, which
  // copies only properties mentioned in `Object.keys()`, when
  // processing the options. So I have to make copies too, rather
  // than using `Object.create()`.
  var sockopts = clone(socketOptions || {});
  url = url || 'amqp://localhost';

  var noDelay = !!sockopts.noDelay;
  var timeout = sockopts.timeout;
  var keepAlive = !!sockopts.keepAlive;
  // 0 is default for node
  var keepAliveDelay = sockopts.keepAliveDelay || 0;

  var extraClientProperties = sockopts.clientProperties || {};

  var protocol, fields;
  if (typeof url === 'object') {
    protocol = (url.protocol || 'amqp') + ':';
    sockopts.host = url.hostname;
    sockopts.servername = sockopts.servername || url.hostname;
    sockopts.port = url.port || ((protocol === 'amqp:') ? 5672 : 5671);

    var user, pass;
    // Only default if both are missing, to have the same behaviour as
    // the stringly URL.
    if (url.username == undefined && url.password == undefined) {
      user = 'guest'; pass = 'guest';
    } else {
      user = url.username || '';
      pass = url.password || '';
    }

    var config = {
      locale: url.locale,
      channelMax: url.channelMax,
      frameMax: url.frameMax,
      heartbeat: url.heartbeat,
    };

    fields = openFrames(url.vhost, config, sockopts.credentials || credentials.plain(user, pass), extraClientProperties);
  } else {
    var parts = URL(url, true); // yes, parse the query string
    protocol = parts.protocol;
    sockopts.host = parts.hostname;
    sockopts.servername = sockopts.servername || parts.hostname;
    sockopts.port = parseInt(parts.port) || ((protocol === 'amqp:') ? 5672 : 5671);
    var vhost = parts.pathname ? parts.pathname.substr(1) : null;
    fields = openFrames(vhost, parts.query, sockopts.credentials || credentialsFromUrl(parts), extraClientProperties);
  }

  var sockok = false;
  var sock;

  function onConnect() {
    sockok = true;
    sock.setNoDelay(noDelay);
    if (keepAlive) sock.setKeepAlive(keepAlive, keepAliveDelay);

    var c = new Connection(sock);
    c.open(fields, function(err, ok) {
      // disable timeout once the connection is open, we don't want
      // it fouling things
      if (timeout) sock.setTimeout(0);
      if (err === null) {
        openCallback(null, c);
      } else {
        // The connection isn't closed by the server on e.g. wrong password
        sock.end();
        sock.destroy();
        openCallback(err);
      }
    });
  }

  if (protocol === 'amqp:') {
    sock = require$$6.connect(sockopts, onConnect);
  }
  else if (protocol === 'amqps:') {
    sock = require$$7.connect(sockopts, onConnect);
  }
  else {
    throw new Error("Expected amqp: or amqps: as the protocol; got " + protocol);
  }

  if (timeout) {
    sock.setTimeout(timeout, function() {
      sock.end();
      sock.destroy();
      openCallback(new Error('connect ETIMEDOUT'));
    });
  }

  sock.once('error', function(err) {
    if (!sockok) openCallback(err);
  });

}

connect$2.connect = connect$1;
connect$2.credentialsFromUrl = credentialsFromUrl;

var channel_model = {};

var channel = {};

var defs$1 = defs$5;
var closeMsg = format$1.closeMessage;
var inspect$1 = format$1.inspect;
var methodName = format$1.methodName;
var assert = require$$0;
var EventEmitter$1 = require$$0$1;
var fmt = require$$1.format;
var IllegalOperationError = error.IllegalOperationError;
var stackCapture = error.stackCapture;

let Channel$1 = class Channel extends EventEmitter$1 {
  constructor (connection) {
    super();

    this.connection = connection;
    // for the presently outstanding RPC
    this.reply = null;
    // for the RPCs awaiting action
    this.pending = [];
    // for unconfirmed messages
    this.lwm = 1; // the least, unconfirmed deliveryTag
    this.unconfirmed = []; // rolling window of delivery callbacks
    this.on('ack', this.handleConfirm.bind(this, function (cb) {
      if (cb)
        cb(null);
    }));
    this.on('nack', this.handleConfirm.bind(this, function (cb) {
      if (cb)
        cb(new Error('message nacked'));
    }));
    this.on('close', function () {
      var cb;
      while (cb = this.unconfirmed.shift()) {
        if (cb)
          cb(new Error('channel closed'));
      }
    });
    // message frame state machine
    this.handleMessage = acceptDeliveryOrReturn;
  }

  setOptions(options) {
    this.options = options;
  }

  allocate () {
    this.ch = this.connection.freshChannel(this, this.options);
    return this;
  }

  // Incoming frames are either notifications of e.g., message delivery,
  // or replies to something we've sent. In general I deal with the
  // former by emitting an event, and with the latter by keeping a track
  // of what's expecting a reply.
  //
  // The AMQP specification implies that RPCs can't be pipelined; that
  // is, you can have only one outstanding RPC on a channel at a
  // time. Certainly that's what RabbitMQ and its clients assume. For
  // this reason, I buffer RPCs if the channel is already waiting for a
  // reply.
  // Just send the damn frame.
  sendImmediately (method, fields) {
    return this.connection.sendMethod(this.ch, method, fields);
  }

  // Invariant: !this.reply -> pending.length == 0. That is, whenever we
  // clear a reply, we must send another RPC (and thereby fill
  // this.reply) if there is one waiting. The invariant relevant here
  // and in `accept`.
  sendOrEnqueue (method, fields, reply) {
    if (!this.reply) { // if no reply waiting, we can go
      assert(this.pending.length === 0);
      this.reply = reply;
      this.sendImmediately(method, fields);
    }
    else {
      this.pending.push({
        method: method,
        fields: fields,
        reply: reply
      });
    }
  }

  sendMessage (fields, properties, content) {
    return this.connection.sendMessage(
      this.ch,
      defs$1.BasicPublish, fields,
      defs$1.BasicProperties, properties,
      content);
  }

  // Internal, synchronously resolved RPC; the return value is resolved
  // with the whole frame.
  _rpc (method, fields, expect, cb) {
    var self = this;

    function reply (err, f) {
      if (err === null) {
        if (f.id === expect) {
          return cb(null, f);
        }
        else {
          // We have detected a problem, so it's up to us to close the
          // channel
          var expectedName = methodName(expect);

          var e = new Error(fmt("Expected %s; got %s",
            expectedName, inspect$1(f, false)));
          self.closeWithError(f.id, fmt('Expected %s; got %s',
            expectedName, methodName(f.id)),
            defs$1.constants.UNEXPECTED_FRAME, e);
          return cb(e);
        }
      }


      // An error will be given if, for example, this is waiting to be
      // sent and the connection closes
      else if (err instanceof Error)
        return cb(err);


      // A close frame will be given if this is the RPC awaiting reply
      // and the channel is closed by the server
      else {
        // otherwise, it's a close frame
        var closeReason = (err.fields.classId << 16) + err.fields.methodId;
        var e = (method === closeReason)
          ? fmt("Operation failed: %s; %s",
            methodName(method), closeMsg(err))
          : fmt("Channel closed by server: %s", closeMsg(err));
        var closeFrameError = new Error(e);
        closeFrameError.code = err.fields.replyCode;
        closeFrameError.classId = err.fields.classId;
        closeFrameError.methodId = err.fields.methodId;
        return cb(closeFrameError);
      }
    }

    this.sendOrEnqueue(method, fields, reply);
  }

  // Move to entirely closed state.
  toClosed (capturedStack) {
    this._rejectPending();
    invalidateSend(this, 'Channel closed', capturedStack);
    this.accept = invalidOp('Channel closed', capturedStack);
    this.connection.releaseChannel(this.ch);
    this.emit('close');
  }

  // Stop being able to send and receive methods and content. Used when
  // we close the channel. Invokes the continuation once the server has
  // acknowledged the close, but before the channel is moved to the
  // closed state.
  toClosing (capturedStack, k) {
    var send = this.sendImmediately.bind(this);
    invalidateSend(this, 'Channel closing', capturedStack);

    this.accept = function (f) {
      if (f.id === defs$1.ChannelCloseOk) {
        if (k)
          k();
        var s = stackCapture('ChannelCloseOk frame received');
        this.toClosed(s);
      }
      else if (f.id === defs$1.ChannelClose) {
        send(defs$1.ChannelCloseOk, {});
      }
      // else ignore frame
    };
  }

  _rejectPending () {
    function rej (r) {
      r(new Error("Channel ended, no reply will be forthcoming"));
    }
    if (this.reply !== null)
      rej(this.reply);
    this.reply = null;

    var discard;
    while (discard = this.pending.shift())
      rej(discard.reply);
    this.pending = null; // so pushes will break
  }

  closeBecause (reason, code, k) {
    this.sendImmediately(defs$1.ChannelClose, {
      replyText: reason,
      replyCode: code,
      methodId: 0, classId: 0
    });
    var s = stackCapture('closeBecause called: ' + reason);
    this.toClosing(s, k);
  }

  // If we close because there's been an error, we need to distinguish
  // between what we tell the server (`reason`) and what we report as
  // the cause in the client (`error`).
  closeWithError (id, reason, code, error) {
    var self = this;
    this.closeBecause(reason, code, function () {
      error.code = code;
      // content frames and consumer errors do not provide a method a class/method ID
      if (id) {
        error.classId = defs$1.info(id).classId;
        error.methodId = defs$1.info(id).methodId;
      }
      self.emit('error', error);
    });
  }

  // A trampolining state machine for message frames on a channel. A
  // message arrives in at least two frames: first, a method announcing
  // the message (either a BasicDeliver or BasicGetOk); then, a message
  // header with the message properties; then, zero or more content
  // frames.
  // Keep the try/catch localised, in an attempt to avoid disabling
  // optimisation
  acceptMessageFrame (f) {
    try {
      this.handleMessage = this.handleMessage(f);
    }
    catch (msg) {
      if (typeof msg === 'string') {
        this.closeWithError(f.id, msg, defs$1.constants.UNEXPECTED_FRAME,
          new Error(msg));
      }
      else if (msg instanceof Error) {
        this.closeWithError(f.id, 'Error while processing message',
          defs$1.constants.INTERNAL_ERROR, msg);
      }
      else {
        this.closeWithError(f.id, 'Internal error while processing message',
          defs$1.constants.INTERNAL_ERROR,
          new Error(msg.toString()));
      }
    }
  }

  handleConfirm (handle, f) {
    var tag = f.deliveryTag;
    var multi = f.multiple;

    if (multi) {
      var confirmed = this.unconfirmed.splice(0, tag - this.lwm + 1);
      this.lwm = tag + 1;
      confirmed.forEach(handle);
    }
    else {
      var c;
      if (tag === this.lwm) {
        c = this.unconfirmed.shift();
        this.lwm++;
        // Advance the LWM and the window to the next non-gap, or
        // possibly to the end
        while (this.unconfirmed[0] === null) {
          this.unconfirmed.shift();
          this.lwm++;
        }
      }
      else {
        c = this.unconfirmed[tag - this.lwm];
        this.unconfirmed[tag - this.lwm] = null;
      }
      // Technically, in the single-deliveryTag case, I should report a
      // protocol breach if it's already been confirmed.
      handle(c);
    }
  }

  pushConfirmCallback (cb) {
    // `null` is used specifically for marking already confirmed slots,
    // so I coerce `undefined` and `null` to false; functions are never
    // falsey.
    this.unconfirmed.push(cb || false);
  }

  onBufferDrain () {
    this.emit('drain');
  }

  accept(f) {

    switch (f.id) {

      // Message frames
    case undefined: // content frame!
    case defs$1.BasicDeliver:
    case defs$1.BasicReturn:
    case defs$1.BasicProperties:
      return this.acceptMessageFrame(f);

      // confirmations, need to do confirm.select first
    case defs$1.BasicAck:
      return this.emit('ack', f.fields);
    case defs$1.BasicNack:
      return this.emit('nack', f.fields);
    case defs$1.BasicCancel:
      // The broker can send this if e.g., the queue is deleted.
      return this.emit('cancel', f.fields);

    case defs$1.ChannelClose:
      // Any remote closure is an error to us. Reject the pending reply
      // with the close frame, so it can see whether it was that
      // operation that caused it to close.
      if (this.reply) {
        var reply = this.reply; this.reply = null;
        reply(f);
      }
      var emsg = "Channel closed by server: " + closeMsg(f);
      this.sendImmediately(defs$1.ChannelCloseOk, {});

      var error = new Error(emsg);
      error.code = f.fields.replyCode;
      error.classId = f.fields.classId;
      error.methodId = f.fields.methodId;
      this.emit('error', error);

      var s = stackCapture(emsg);
      this.toClosed(s);
      return;

    case defs$1.BasicFlow:
      // RabbitMQ doesn't send this, it just blocks the TCP socket
      return this.closeWithError(f.id, "Flow not implemented",
                                 defs$1.constants.NOT_IMPLEMENTED,
                                 new Error('Flow not implemented'));

    default: // assume all other things are replies
      // Resolving the reply may lead to another RPC; to make sure we
      // don't hold that up, clear this.reply
      var reply = this.reply; this.reply = null;
      // however, maybe there's an RPC waiting to go? If so, that'll
      // fill this.reply again, restoring the invariant. This does rely
      // on any response being recv'ed after resolving the promise,
      // below; hence, I use synchronous defer.
      if (this.pending.length > 0) {
        var send = this.pending.shift();
        this.reply = send.reply;
        this.sendImmediately(send.method, send.fields);
      }
      return reply(null, f);
    }
  }
};

// Shutdown protocol. There's three scenarios:
//
// 1. The application decides to shut the channel
// 2. The server decides to shut the channel, possibly because of
// something the application did
// 3. The connection is closing, so there won't be any more frames
// going back and forth.
//
// 1 and 2 involve an exchange of method frames (Close and CloseOk),
// while 3 doesn't; the connection simply says "shutdown" to the
// channel, which then acts as if it's closing, without going through
// the exchange.

function invalidOp(msg, stack) {
  return function() {
    throw new IllegalOperationError(msg, stack);
  };
}

function invalidateSend(ch, msg, stack) {
  ch.sendImmediately = ch.sendOrEnqueue = ch.sendMessage =
    invalidOp(msg, stack);
}

// Kick off a message delivery given a BasicDeliver or BasicReturn
// frame (BasicGet uses the RPC mechanism)
function acceptDeliveryOrReturn(f) {
  var event;
  if (f.id === defs$1.BasicDeliver) event = 'delivery';
  else if (f.id === defs$1.BasicReturn) event = 'return';
  else throw fmt("Expected BasicDeliver or BasicReturn; got %s",
                 inspect$1(f));

  var self = this;
  var fields = f.fields;
  return acceptMessage$1(function(message) {
    message.fields = fields;
    self.emit(event, message);
  });
}

// Move to the state of waiting for message frames (headers, then
// one or more content frames)
function acceptMessage$1(continuation) {
  var totalSize = 0, remaining = 0;
  var buffers = null;

  var message = {
    fields: null,
    properties: null,
    content: null
  };

  return headers;

  // expect a headers frame
  function headers(f) {
    if (f.id === defs$1.BasicProperties) {
      message.properties = f.fields;
      totalSize = remaining = f.size;

      // for zero-length messages, content frames aren't required.
      if (totalSize === 0) {
        message.content = Buffer.alloc(0);
        continuation(message);
        return acceptDeliveryOrReturn;
      }
      else {
        return content;
      }
    }
    else {
      throw "Expected headers frame after delivery";
    }
  }

  // expect a content frame
  // %%% TODO cancelled messages (sent as zero-length content frame)
  function content(f) {
    if (f.content) {
      var size = f.content.length;
      remaining -= size;
      if (remaining === 0) {
        if (buffers !== null) {
          buffers.push(f.content);
          message.content = Buffer.concat(buffers);
        }
        else {
          message.content = f.content;
        }
        continuation(message);
        return acceptDeliveryOrReturn;
      }
      else if (remaining < 0) {
        throw fmt("Too much content sent! Expected %d bytes",
                  totalSize);
      }
      else {
        if (buffers !== null)
          buffers.push(f.content);
        else
          buffers = [f.content];
        return content;
      }
    }
    else throw "Expected content frame after headers"
  }
}

// This adds just a bit more stuff useful for the APIs, but not
// low-level machinery.
let BaseChannel$1 = class BaseChannel extends Channel$1 {
  constructor (connection) {
    super(connection);
    this.consumers = new Map();
  }

  // Not sure I like the ff, it's going to be changing hidden classes
  // all over the place. On the other hand, whaddya do.
  registerConsumer (tag, callback) {
    this.consumers.set(tag, callback);
  }

  unregisterConsumer (tag) {
    this.consumers.delete(tag);
  }

  dispatchMessage (fields, message) {
    var consumerTag = fields.consumerTag;
    var consumer = this.consumers.get(consumerTag);
    if (consumer) {
      return consumer(message);
    }
    else {
      // %%% Surely a race here
      throw new Error("Unknown consumer: " + consumerTag);
    }
  }

  handleDelivery (message) {
    return this.dispatchMessage(message.fields, message);
  }

  handleCancel (fields) {
    var result = this.dispatchMessage(fields, null);
    this.unregisterConsumer(fields.consumerTag);
    return result;
  }
};

channel.acceptMessage = acceptMessage$1;
channel.BaseChannel = BaseChannel$1;
channel.Channel = Channel$1;

/*
The channel (promise) and callback APIs have similar signatures, and
in particular, both need AMQP fields prepared from the same arguments
and options. The arguments marshalling is done here. Each of the
procedures below takes arguments and options (the latter in an object)
particular to the operation it represents, and returns an object with
fields for handing to the encoder.
*/

// A number of AMQP methods have a table-typed field called
// `arguments`, that is intended to carry extension-specific
// values. RabbitMQ uses this in a number of places; e.g., to specify
// an 'alternate exchange'.
//
// Many of the methods in this API have an `options` argument, from
// which I take both values that have a default in AMQP (e.g.,
// autoDelete in QueueDeclare) *and* values that are specific to
// RabbitMQ (e.g., 'alternate-exchange'), which would normally be
// supplied in `arguments`. So that extensions I don't support yet can
// be used, I include `arguments` itself among the options.
//
// The upshot of this is that I often need to prepare an `arguments`
// value that has any values passed in `options.arguments` as well as
// any I've promoted to being options themselves. Since I don't want
// to mutate anything passed in, the general pattern is to create a
// fresh object with the `arguments` value given as its prototype; all
// fields in the supplied value will be serialised, as well as any I
// set on the fresh object. What I don't want to do, however, is set a
// field to undefined by copying possibly missing field values,
// because that will mask a value in the prototype.
//
// NB the `arguments` field already has a default value of `{}`, so
// there's no need to explicitly default it unless I'm setting values.
function setIfDefined(obj, prop, value) {
  if (value != undefined) obj[prop] = value;
}

var EMPTY_OPTIONS = Object.freeze({});

var Args$1 = {};

Args$1.assertQueue = function(queue, options) {
  queue = queue || '';
  options = options || EMPTY_OPTIONS;

  var argt = Object.create(options.arguments || null);
  setIfDefined(argt, 'x-expires', options.expires);
  setIfDefined(argt, 'x-message-ttl', options.messageTtl);
  setIfDefined(argt, 'x-dead-letter-exchange',
               options.deadLetterExchange);
  setIfDefined(argt, 'x-dead-letter-routing-key',
               options.deadLetterRoutingKey);
  setIfDefined(argt, 'x-max-length', options.maxLength);
  setIfDefined(argt, 'x-max-priority', options.maxPriority);
  setIfDefined(argt, 'x-overflow', options.overflow);
  setIfDefined(argt, 'x-queue-mode', options.queueMode);

  return {
    queue: queue,
    exclusive: !!options.exclusive,
    durable: (options.durable === undefined) ? true : options.durable,
    autoDelete: !!options.autoDelete,
    arguments: argt,
    passive: false,
    // deprecated but we have to include it
    ticket: 0,
    nowait: false
  };
};

Args$1.checkQueue = function(queue) {
  return {
    queue: queue,
    passive: true, // switch to "completely different" mode
    nowait: false,
    durable: true, autoDelete: false, exclusive: false, // ignored
    ticket: 0,
  };
};

Args$1.deleteQueue = function(queue, options) {
  options = options || EMPTY_OPTIONS;
  return {
    queue: queue,
    ifUnused: !!options.ifUnused,
    ifEmpty: !!options.ifEmpty,
    ticket: 0, nowait: false
  };
};

Args$1.purgeQueue = function(queue) {
  return {
    queue: queue,
    ticket: 0, nowait: false
  };
};

Args$1.bindQueue = function(queue, source, pattern, argt) {
  return {
    queue: queue,
    exchange: source,
    routingKey: pattern,
    arguments: argt,
    ticket: 0, nowait: false
  };
};

Args$1.unbindQueue = function(queue, source, pattern, argt) {
  return {
    queue: queue,
    exchange: source,
    routingKey: pattern,
    arguments: argt,
    ticket: 0, nowait: false
  };
};

Args$1.assertExchange = function(exchange, type, options) {
  options = options || EMPTY_OPTIONS;
  var argt = Object.create(options.arguments || null);
  setIfDefined(argt, 'alternate-exchange', options.alternateExchange);
  return {
    exchange: exchange,
    ticket: 0,
    type: type,
    passive: false,
    durable: (options.durable === undefined) ? true : options.durable,
    autoDelete: !!options.autoDelete,
    internal: !!options.internal,
    nowait: false,
    arguments: argt
  };
};

Args$1.checkExchange = function(exchange) {
  return {
    exchange: exchange,
    passive: true, // switch to 'may as well be another method' mode
    nowait: false,
    // ff are ignored
    durable: true, internal: false,  type: '',  autoDelete: false,
    ticket: 0
  };
};

Args$1.deleteExchange = function(exchange, options) {
  options = options || EMPTY_OPTIONS;
  return {
    exchange: exchange,
    ifUnused: !!options.ifUnused,
    ticket: 0, nowait: false
  };
};

Args$1.bindExchange = function(dest, source, pattern, argt) {
  return {
    source: source,
    destination: dest,
    routingKey: pattern,
    arguments: argt,
    ticket: 0, nowait: false
  };
};

Args$1.unbindExchange = function(dest, source, pattern, argt) {
  return {
    source: source,
    destination: dest,
    routingKey: pattern,
    arguments: argt,
    ticket: 0, nowait: false
  };
};

// It's convenient to construct the properties and the method fields
// at the same time, since in the APIs, values for both can appear in
// `options`. Since the property or mthod field names don't overlap, I
// just return one big object that can be used for both purposes, and
// the encoder will pick out what it wants.
Args$1.publish = function(exchange, routingKey, options) {
  options = options || EMPTY_OPTIONS;

  // The CC and BCC fields expect an array of "longstr", which would
  // normally be buffer values in JavaScript; however, since a field
  // array (or table) cannot have shortstr values, the codec will
  // encode all strings as longstrs anyway.
  function convertCC(cc) {
    if (cc === undefined) {
      return undefined;
    }
    else if (Array.isArray(cc)) {
      return cc.map(String);
    }
    else return [String(cc)];
  }

  var headers = Object.create(options.headers || null);
  setIfDefined(headers, 'CC', convertCC(options.CC));
  setIfDefined(headers, 'BCC', convertCC(options.BCC));

  var deliveryMode; // undefined will default to 1 (non-persistent)

  // Previously I overloaded deliveryMode be a boolean meaning
  // 'persistent or not'; better is to name this option for what it
  // is, but I need to have backwards compatibility for applications
  // that either supply a numeric or boolean value.
  if (options.persistent !== undefined)
    deliveryMode = (options.persistent) ? 2 : 1;
  else if (typeof options.deliveryMode === 'number')
    deliveryMode = options.deliveryMode;
  else if (options.deliveryMode) // is supplied and truthy
    deliveryMode = 2;

  var expiration = options.expiration;
  if (expiration !== undefined) expiration = expiration.toString();

  return {
    // method fields
    exchange: exchange,
    routingKey: routingKey,
    mandatory: !!options.mandatory,
    immediate: false, // RabbitMQ doesn't implement this any more
    ticket: undefined,
    // properties
    contentType: options.contentType,
    contentEncoding: options.contentEncoding,
    headers: headers,
    deliveryMode: deliveryMode,
    priority: options.priority,
    correlationId: options.correlationId,
    replyTo: options.replyTo,
    expiration: expiration,
    messageId: options.messageId,
    timestamp: options.timestamp,
    type: options.type,
    userId: options.userId,
    appId: options.appId,
    clusterId: undefined
  };
};

Args$1.consume = function(queue, options) {
  options = options || EMPTY_OPTIONS;
  var argt = Object.create(options.arguments || null);
  setIfDefined(argt, 'x-priority', options.priority);
  return {
    ticket: 0,
    queue: queue,
    consumerTag: options.consumerTag || '',
    noLocal: !!options.noLocal,
    noAck: !!options.noAck,
    exclusive: !!options.exclusive,
    nowait: false,
    arguments: argt
  };
};

Args$1.cancel = function(consumerTag) {
  return {
    consumerTag: consumerTag,
    nowait: false
  };
};

Args$1.get = function(queue, options) {
  options = options || EMPTY_OPTIONS;
  return {
    ticket: 0,
    queue: queue,
    noAck: !!options.noAck
  };
};

Args$1.ack = function(tag, allUpTo) {
  return {
    deliveryTag: tag,
    multiple: !!allUpTo
  };
};

Args$1.nack = function(tag, allUpTo, requeue) {
  return {
    deliveryTag: tag,
    multiple: !!allUpTo,
    requeue: (requeue === undefined) ? true : requeue
  };
};

Args$1.reject = function(tag, requeue) {
  return {
    deliveryTag: tag,
    requeue: (requeue === undefined) ? true : requeue
  };
};

Args$1.prefetch = function(count, global) {
  return {
    prefetchCount: count || 0,
    prefetchSize: 0,
    global: !!global
  };
};

Args$1.recover = function() {
  return {requeue: true};
};

var api_args = Object.freeze(Args$1);

const EventEmitter = require$$0$1;
const promisify$1 = require$$1.promisify;
const defs = defs$5;
const {BaseChannel} = channel;
const {acceptMessage} = channel;
const Args = api_args;
const {inspect} = format$1;

let ChannelModel$1 = class ChannelModel extends EventEmitter {
  constructor(connection) {
    super();
    this.connection = connection;

    ['error', 'close', 'blocked', 'unblocked'].forEach(ev => {
      connection.on(ev, this.emit.bind(this, ev));
    });
  }

  close() {
    return promisify$1(this.connection.close.bind(this.connection))();
  }

  updateSecret(newSecret, reason) {
    return promisify$1(this.connection._updateSecret.bind(this.connection))(newSecret, reason);
  }

  async createChannel(options) {
    const channel = new Channel(this.connection);
    channel.setOptions(options);
    await channel.open();
    return channel;
  }

  async createConfirmChannel(options) {
    const channel = new ConfirmChannel(this.connection);
    channel.setOptions(options);
    await channel.open();
    await channel.rpc(defs.ConfirmSelect, {nowait: false}, defs.ConfirmSelectOk);
    return channel;
  }
};

// Channels

class Channel extends BaseChannel {
  constructor(connection) {
    super(connection);
    this.on('delivery', this.handleDelivery.bind(this));
    this.on('cancel', this.handleCancel.bind(this));
  }

  // An RPC that returns a 'proper' promise, which resolves to just the
  // response's fields; this is intended to be suitable for implementing
  // API procedures.
  async rpc(method, fields, expect) {
    const f = await promisify$1(cb => {
      return this._rpc(method, fields, expect, cb);
    })();

    return f.fields;
  }

  // Do the remarkably simple channel open handshake
  async open() {
    const ch = await this.allocate.bind(this)();
    return ch.rpc(defs.ChannelOpen, {outOfBand: ""},
                  defs.ChannelOpenOk);
  }

  close() {
    return promisify$1(cb => {
      return this.closeBecause("Goodbye", defs.constants.REPLY_SUCCESS,
                      cb);
    })();
  }

  // === Public API, declaring queues and stuff ===

  assertQueue(queue, options) {
    return this.rpc(defs.QueueDeclare,
                    Args.assertQueue(queue, options),
                    defs.QueueDeclareOk);
  }

  checkQueue(queue) {
    return this.rpc(defs.QueueDeclare,
                    Args.checkQueue(queue),
                    defs.QueueDeclareOk);
  }

  deleteQueue(queue, options) {
    return this.rpc(defs.QueueDelete,
                    Args.deleteQueue(queue, options),
                    defs.QueueDeleteOk);
  }

  purgeQueue(queue) {
    return this.rpc(defs.QueuePurge,
                    Args.purgeQueue(queue),
                    defs.QueuePurgeOk);
  }

  bindQueue(queue, source, pattern, argt) {
    return this.rpc(defs.QueueBind,
                    Args.bindQueue(queue, source, pattern, argt),
                    defs.QueueBindOk);
  }

  unbindQueue(queue, source, pattern, argt) {
    return this.rpc(defs.QueueUnbind,
                    Args.unbindQueue(queue, source, pattern, argt),
                    defs.QueueUnbindOk);
  }

  assertExchange(exchange, type, options) {
    // The server reply is an empty set of fields, but it's convenient
    // to have the exchange name handed to the continuation.
    return this.rpc(defs.ExchangeDeclare,
                    Args.assertExchange(exchange, type, options),
                    defs.ExchangeDeclareOk)
      .then(_ok => { return { exchange }; });
  }

  checkExchange(exchange) {
    return this.rpc(defs.ExchangeDeclare,
                    Args.checkExchange(exchange),
                    defs.ExchangeDeclareOk);
  }

  deleteExchange(name, options) {
    return this.rpc(defs.ExchangeDelete,
                    Args.deleteExchange(name, options),
                    defs.ExchangeDeleteOk);
  }

  bindExchange(dest, source, pattern, argt) {
    return this.rpc(defs.ExchangeBind,
                    Args.bindExchange(dest, source, pattern, argt),
                    defs.ExchangeBindOk);
  }

  unbindExchange(dest, source, pattern, argt) {
    return this.rpc(defs.ExchangeUnbind,
                    Args.unbindExchange(dest, source, pattern, argt),
                    defs.ExchangeUnbindOk);
  }

  // Working with messages

  publish(exchange, routingKey, content, options) {
    const fieldsAndProps = Args.publish(exchange, routingKey, options);
    return this.sendMessage(fieldsAndProps, fieldsAndProps, content);
  }

  sendToQueue(queue, content, options) {
    return this.publish('', queue, content, options);
  }

  consume(queue, callback, options) {
    // NB we want the callback to be run synchronously, so that we've
    // registered the consumerTag before any messages can arrive.
    const fields = Args.consume(queue, options);
    return new Promise((resolve, reject) => {
      this._rpc(defs.BasicConsume, fields, defs.BasicConsumeOk, (err, ok) => {
        if (err) return reject(err);
        this.registerConsumer(ok.fields.consumerTag, callback);
        resolve(ok.fields);
      });
    });
  }

  async cancel(consumerTag) {
    await promisify$1(cb => {
      this._rpc(defs.BasicCancel, Args.cancel(consumerTag),
            defs.BasicCancelOk,
            cb);
    })()
    .then(ok => {
      this.unregisterConsumer(consumerTag);
      return ok.fields;
    });
  }

  get(queue, options) {
    const fields = Args.get(queue, options);
    return new Promise((resolve, reject) => {
      this.sendOrEnqueue(defs.BasicGet, fields, (err, f) => {
        if (err) return reject(err);
        if (f.id === defs.BasicGetEmpty) {
          return resolve(false);
        }
        else if (f.id === defs.BasicGetOk) {
          const fields = f.fields;
          this.handleMessage = acceptMessage(m => {
            m.fields = fields;
            resolve(m);
          });
        }
        else {
          reject(new Error(`Unexpected response to BasicGet: ${inspect(f)}`));
        }
      });
    });
  }

  ack(message, allUpTo) {
    this.sendImmediately(
      defs.BasicAck,
      Args.ack(message.fields.deliveryTag, allUpTo));
  }

  ackAll() {
    this.sendImmediately(defs.BasicAck, Args.ack(0, true));
  }

  nack(message, allUpTo, requeue) {
    this.sendImmediately(
      defs.BasicNack,
      Args.nack(message.fields.deliveryTag, allUpTo, requeue));
  }

  nackAll(requeue) {
    this.sendImmediately(defs.BasicNack,
                         Args.nack(0, true, requeue));
  }

  // `Basic.Nack` is not available in older RabbitMQ versions (or in the
  // AMQP specification), so you have to use the one-at-a-time
  // `Basic.Reject`. This is otherwise synonymous with
  // `#nack(message, false, requeue)`.
  reject(message, requeue) {
    this.sendImmediately(
      defs.BasicReject,
      Args.reject(message.fields.deliveryTag, requeue));
  }

  recover() {
    return this.rpc(defs.BasicRecover,
                    Args.recover(),
                    defs.BasicRecoverOk);
  }

  qos(count, global) {
    return this.rpc(defs.BasicQos,
                    Args.prefetch(count, global),
                    defs.BasicQosOk);
  }
}

// There are more options in AMQP than exposed here; RabbitMQ only
// implements prefetch based on message count, and only for individual
// channels or consumers. RabbitMQ v3.3.0 and after treat prefetch
// (without `global` set) as per-consumer (for consumers following),
// and prefetch with `global` set as per-channel.
Channel.prototype.prefetch = Channel.prototype.qos;

// Confirm channel. This is a channel with confirms 'switched on',
// meaning sent messages will provoke a responding 'ack' or 'nack'
// from the server. The upshot of this is that `publish` and
// `sendToQueue` both take a callback, which will be called either
// with `null` as its argument to signify 'ack', or an exception as
// its argument to signify 'nack'.

class ConfirmChannel extends Channel {
  publish(exchange, routingKey, content, options, cb) {
    this.pushConfirmCallback(cb);
    return super.publish(exchange, routingKey, content, options);
  }

  sendToQueue(queue, content, options, cb) {
    return this.publish('', queue, content, options, cb);
  }

  waitForConfirms() {
    const awaiting = [];
    const unconfirmed = this.unconfirmed;
    unconfirmed.forEach((val, index) => {
      if (val !== null) {
        const confirmed = new Promise((resolve, reject) => {
          unconfirmed[index] = err => {
            if (val) val(err);
            if (err === null) resolve();
            else reject(err);
          };
        });
        awaiting.push(confirmed);
      }
    });
    // Channel closed
    if (!this.pending) {
      var cb;
      while (cb = this.unconfirmed.shift()) {
        if (cb) cb(new Error('channel closed'));
      }
    }
    return Promise.all(awaiting);
  }
}

channel_model.ConfirmChannel = ConfirmChannel;
channel_model.Channel = Channel;
channel_model.ChannelModel = ChannelModel$1;

var raw_connect = connect$2.connect;
var ChannelModel = channel_model.ChannelModel;
var promisify = require$$1.promisify;

function connect(url, connOptions) {
  return promisify(function(cb) {
    return raw_connect(url, connOptions, cb);
  })()
  .then(function(conn) {
    return new ChannelModel(conn);
  });
}
var connect_1 = connect;

const DEFUALT_BATCH_TIMEOUT = 2000;
class AMQPClient {
    constructor({ logger = console, ...options }) {
        this.connection = null;
        this.producer = null;
        this.consumers = new Map();
        this.reconnectAttempts = 0;
        // Define default options
        const defaultOptions = {
            reconnection: {
                initialDelay: 1000,
                maxDelay: 32000,
                maxAttempts: 50,
            },
        };
        this.options = {
            ...options,
            reconnection: {
                ...defaultOptions.reconnection,
                ...(options.reconnection ?? {}),
            },
            // This config must remain constant between all the services using the queue, that's why is constant.
            messageExpiration: {
                // Within 24 hours, a message has 3 attempts to be consumed. If not, it will be sent to the dead letter queue.
                // We have 30 days to analyze what's going on with the discarded message. If not, it will be discarded.
                queueTTL: 24 * 60 * 60 * 1000,
                deadLetterQueueTTL: 30 * 24 * 60 * 60 * 1000,
                defaultMaxRetries: 3,
            },
        };
        this.logger = logger;
    }
    async connect(connectionName, applicationName) {
        const { host, port = 5672, username, password, vhost = '/' } = this.options;
        const connectionString = `amqp://${username ? `${username}:${password}@` : ''}${host}:${port}/${vhost}`;
        try {
            this.connection = await connect_1(connectionString, {
                clientProperties: {
                    connection_name: connectionName,
                    application: applicationName,
                },
            });
            this.reconnectAttempts = 0;
            this.logger.info('📭️ Connected to AMQP broker.');
            this.connection.on('error', (err) => {
                this.logger.error('🚨 AMQP Connection Error:', err);
                this.reconnect(connectionName);
            });
            this.connection.on('close', () => {
                this.logger.warn('⚠️ AMQP Connection Closed');
                this.reconnect(connectionName);
            });
        }
        catch (error) {
            this.logger.error('🚨 Failed to connect to AMQP broker:', error);
            await this.reconnect(connectionName);
        }
    }
    async reconnect(queueName) {
        if (this.reconnectAttempts >= this.options.reconnection.maxAttempts) {
            this.logger.error('🚨 Max reconnection attempts reached. Giving up.');
            return;
        }
        const delay = this.calculateBackoffDelay(this.reconnectAttempts);
        this.reconnectAttempts++;
        this.logger.warn(`⚠️ Reconnecting (Attempt ${this.reconnectAttempts})`);
        return new Promise((resolve) => {
            setTimeout(async () => {
                try {
                    await this.connect(queueName);
                    resolve();
                }
                catch (err) {
                    this.logger.error('🚨 Reconnection failed:', err);
                    resolve();
                }
            }, delay);
        });
    }
    calculateBackoffDelay(attempt) {
        const exponentialDelay = Math.min(this.options.reconnection.maxDelay, this.options.reconnection.initialDelay * Math.pow(2, attempt));
        return Math.ceil(exponentialDelay + Math.random() * 1000);
    }
    async close() {
        try {
            if (this.producer) {
                await this.producer.close();
                this.producer = null;
            }
            this.logger.info('📪️ AMQP producer channel closed.');
        }
        catch (error) {
            this.logger.error('🚨 Error closing AMQP producer channel:', error);
        }
        try {
            if (this.consumers.size) {
                await Promise.all(Array.from(this.consumers.values()).map(async (channel) => channel.close()));
            }
            this.logger.info('📪️ AMQP consumer channels closed.');
        }
        catch (error) {
            this.logger.error('🚨 Error closing AMQP consumer channels:', error);
        }
        try {
            if (this.connection) {
                await this.connection.close();
            }
            this.logger.info('📪️ AMQP connection closed.');
        }
        catch (error) {
            this.logger.error('🚨 Error closing AMQP connection:', error);
        }
        finally {
            this.connection = null;
        }
    }
    async sendMessage(queueName, message, { headers, correlationId } = {}) {
        try {
            if (!this.producer) {
                this.producer = await this.getProducerChannel(queueName);
            }
            this.logger.debug(`📨 Sending message to queue: ${queueName}`);
            return this.producer.sendToQueue(queueName, Buffer.from(JSON.stringify(message)), {
                headers,
                correlationId,
                persistent: true,
                deliveryMode: 2,
                contentType: 'application/json',
                expiration: this.options.messageExpiration.queueTTL,
            });
        }
        catch (error) {
            this.logger.error(`💥 Failed sending message to queue: ${queueName}`, JSON.stringify(error, null, 2));
        }
        return false;
    }
    async createListener(queueName, onMessage, options) {
        const channel = await this.getConsumerChannel({
            queueName,
            deadLetter: options?.deadLetter !== undefined ? options.deadLetter : true,
            prefetch: options?.batchSize ?? 1,
        });
        if (options?.batchSize && options.batchSize > 1) {
            return await this.batchListener(queueName, channel, onMessage, options);
        }
        else {
            await channel.consume(queueName, async (msg) => {
                this.logger.info(`📬️ Starting to consume messages from queue: ${queueName}`);
                await this.processSingleMessage(queueName, msg, channel, onMessage, options);
            });
        }
    }
    async batchListener(queueName, channel, onMessage, options) {
        if (!options?.batchSize) {
            throw new Error('Batch size must be defined for batch listener');
        }
        const batch = [];
        const processBatch = async () => {
            try {
                await Promise.allSettled(batch.map(async (msg) => {
                    return await this.processSingleMessage(queueName, msg, channel, onMessage, options);
                }));
            }
            catch (error) {
                this.logger.error('🚨 Error processing batch:', error);
            }
            finally {
                batch.length = 0;
            }
        };
        let timer = null;
        const setTimer = () => {
            timer = setInterval(() => {
                if (batch.length > 0) {
                    processBatch();
                }
            }, options?.batchTimeout ?? DEFUALT_BATCH_TIMEOUT);
        };
        const clearTimer = () => {
            if (timer) {
                clearInterval(timer);
                timer = null;
            }
        };
        setTimer();
        await channel.consume(queueName, async (msg) => {
            if (!msg)
                return;
            batch.push(msg);
            if (batch.length >= options.batchSize) {
                clearTimer();
                await processBatch();
                setTimer();
            }
        });
    }
    async processSingleMessage(queueName, msg, channel, onMessage, options) {
        if (!msg) {
            return;
        }
        if (options?.correlationId && options.correlationId !== msg.properties.correlationId) {
            channel.nack(msg, false, true);
            return;
        }
        try {
            const content = JSON.parse(msg.content.toString());
            const message = {
                content,
                metadata: {
                    headers: msg.properties.headers,
                    correlationId: msg.properties.correlationId,
                    redelivered: msg.fields.redelivered,
                },
            };
            const deathCount = msg.properties.headers?.['x-delivery-count'] || 0;
            const attempts = deathCount + 1;
            const result = await onMessage(message);
            if (!result) {
                const requeue = attempts <= this.options.messageExpiration.defaultMaxRetries;
                channel.nack(msg, false, requeue);
                if (!requeue) {
                    this.logger.warn(`⚠️ Message exceeded retry limit (${this.options.messageExpiration.defaultMaxRetries}) and will be moved to DLQ: ${queueName}.dlq`);
                }
            }
            else {
                channel.ack(msg);
                this.logger.debug(`✅ Message successfully processed`);
            }
        }
        catch (error) {
            this.logger.error('🚨 Message processing error:', error);
            channel.nack(msg, false, false);
        }
    }
    async getProducerChannel(queueName) {
        this.logger.debug(`🗿 Creating new producer Channel`);
        if (!this.connection) {
            await this.connect(queueName);
        }
        let producer;
        if (this.connection) {
            producer = await this.connection.createChannel();
            producer.on('error', (err) => {
                this.logger.error('🚨 AMQP Channel Error:', err);
                this.producer = null;
            });
            producer.on('close', () => {
                this.logger.warn('⚠️ AMQP Channel Closed');
                this.producer = null;
            });
        }
        if (!producer) {
            throw new Error('💥 Channel is not available');
        }
        return producer;
    }
    async getConsumerChannel({ queueName, deadLetter, prefetch, }) {
        this.logger.debug(`🗿 Asserting queue ${queueName} ${deadLetter ? 'with dead letter queue' : ''}`);
        const channelQueueName = `consumer-${queueName}-${Date.now()}`;
        const channel = await this.createConsumerChannel(channelQueueName, prefetch);
        const assertQueueOptions = {
            durable: true,
            exclusive: false,
            arguments: {
                'x-queue-type': 'quorum',
                'x-max-retries': this.options.messageExpiration.defaultMaxRetries,
            },
        };
        const exchangeName = `${queueName}.dlx`;
        const dlqName = `${queueName}.dlq`;
        const routingKey = `${queueName}.dead`;
        if (deadLetter) {
            assertQueueOptions.deadLetterExchange = exchangeName;
            assertQueueOptions.deadLetterRoutingKey = routingKey;
            assertQueueOptions.arguments = {
                ...assertQueueOptions.arguments,
                'x-dead-letter-exchange': exchangeName,
                'x-dead-letter-routing-key': routingKey,
            };
        }
        try {
            this.logger.debug(`🗿 Asserting queue "${queueName}"`);
            await this.bindQueueToChannel({
                channel,
                queueName,
                assertQueueOptions,
                deadLetter,
                exchangeName,
                dlqName,
                routingKey,
            });
            return channel;
        }
        catch (error) {
            // PRECONDITION_FAILED ERROR | QUEUE EXISTS WITH DIFFERENT CONFIG
            if (this.isAmqpError(error) && error.code === 406) {
                this.logger.warn(`⚠️ Queue "${queueName}" exists with different arguments.`);
                try {
                    // WE NEED TO RECREATE THE CHANNEL. WHENEVER ASSERT QUEUE THROWS AN ERROR, THE CHANNEL BREAKS
                    const channel = await this.createConsumerChannel(channelQueueName, prefetch);
                    const queue = await channel.checkQueue(queueName);
                    if (queue.messageCount === 0) {
                        this.logger.info(`🔄 Queue "${queueName}" is empty. Recreating it with new arguments.`);
                        await channel.deleteQueue(queueName);
                        await this.bindQueueToChannel({
                            channel,
                            queueName,
                            assertQueueOptions,
                            deadLetter,
                            exchangeName,
                            dlqName,
                            routingKey,
                        });
                        return channel;
                    }
                    else {
                        this.logger.warn(`⚠️ Queue "${queueName}" has messages. Proceeding without re-declaring the queue.`);
                        return channel;
                    }
                }
                catch (checkError) {
                    this.logger.error(`💥 Failed recreating queue "${queueName}":`, checkError);
                    throw checkError;
                }
            }
            else {
                throw error;
            }
        }
    }
    async bindQueueToChannel({ channel, queueName, assertQueueOptions, deadLetter, exchangeName, dlqName, routingKey, }) {
        await channel.assertQueue(queueName, assertQueueOptions);
        if (deadLetter) {
            this.logger.debug(`🗿 Asserting exchange "${exchangeName}"`);
            await channel.assertExchange(exchangeName, 'direct', {
                durable: true,
                autoDelete: false,
            });
            this.logger.debug(`🗿 Asserting and binding dead letter queue "${dlqName}"`);
            await channel.assertQueue(dlqName, {
                durable: true,
                arguments: {
                    'x-queue-type': 'quorum',
                    'x-message-ttl': this.options.messageExpiration.deadLetterQueueTTL,
                },
            });
            await channel.bindQueue(dlqName, exchangeName, routingKey);
        }
    }
    async createConsumerChannel(queueName, prefetch) {
        this.logger.debug(`🗿 Creating new consumer Channel for "${queueName}"`);
        if (!this.connection) {
            await this.connect(queueName);
        }
        let channel;
        if (this.connection) {
            channel = await this.connection.createChannel();
            if (prefetch) {
                await channel.prefetch(prefetch);
            }
            channel.on('error', (err) => {
                this.logger.error('🚨 AMQP Channel Error:', err);
                this.consumers.delete(queueName);
            });
            channel.on('close', () => {
                this.logger.warn('⚠️ AMQP Channel Closed');
                this.consumers.delete(queueName);
            });
            this.consumers.set(queueName, channel);
        }
        if (!channel) {
            throw new Error('💥 Channel is not available');
        }
        return channel;
    }
    isAmqpError(error) {
        return typeof error === 'object' && error !== null && 'code' in error;
    }
}

export { AMQPClient };
