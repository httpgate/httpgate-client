#!/usr/bin/env node

const args = require('args');
var http = require('http');
var dns = require('dns');
var debug = require('debug')('proxy');
debug.log = console.info.bind(console);

args.option(
	'domain',
	'domain of a Cloudflare worker site runs httpgate script',
	'',
	String
).option(
		'local-address',
		'IP address of the network interface to send the outgoing requests through',
		'127.0.0.1',
		String
).option(
	'port',
	'Port number to the proxy server should bind to',
	5013,
	parseInt
).option(
	'root',
	'root path of proxy url',
	'127.0.0.1',
	String
);

const flags = args.parse(process.argv);
/**
 * Setup the HTTP "proxy server" instance.
 */
dns.setServers(['8.8.4.4']);

function lookup(hostname, opts, cb) {
	dns.lookup(hostname, opts, function(err, results) {
	  if (err) return cb(err);
	  cb(null, results, 4);
	})
}

const proxy = http.createServer();
setup(proxy);

/**
 * Proxy outgoing request localAddress parameter
 */

if (flags.localAddress) {
	proxy.localAddress = flags.localAddress;
}

/**
 * Bind to port.
 */

proxy.listen(flags.port, flags.localAddress, function() {
	console.log(
		'HTTP(s) proxy server listening on host %s port %d', this.address().address,
		this.address().port
	);
});

/**
 * Module dependencies.
 */
var stream = require('stream');
var util = require('util');
var net = require('net');
var assert = require('assert');
var https = require('https');
var url = require('url');
//const { stringify } = require('querystring');
var zlib = require('zlib');

function bfReplace(buf, a, b) {
	if (!Buffer.isBuffer(buf))
	 buf = Buffer.from(buf);
	const idx = buf.indexOf(a);
	if (idx === -1) return buf;
	if (!Buffer.isBuffer(b)) b = Buffer.from(b);

	const before = buf.slice(0, idx);
	const after = bfReplace(buf.slice(idx + a.length), a, b);
	const len = idx + b.length + after.length;
	return Buffer.concat([before, b, after], len);
}

strHTTPS = Buffer.from('https://');
strHTTP = Buffer.from('http://');

// node v0.10+ use native Transform, else polyfill
var Transform = stream.Transform ||
	require('readable-stream').Transform;

function Https2http(options) {
	// allow use without new
	if (!(this instanceof Https2http)) {
		return new Https2http(options);
	}
	// init Transform
	Transform.call(this, options);
}
util.inherits(Https2http, Transform);

Https2http.prototype._transform = function (chunk, enc, cb) {
	buf = bfReplace(chunk, strHTTPS, strHTTP);
	this.push(buf);
	cb();
};

// log levels
debug.request = require('debug')('proxy ← ← ←');
debug.response = require('debug')('proxy → → →');
debug.proxyRequest = require('debug')('proxy ↑ ↑ ↑');
debug.proxyResponse = require('debug')('proxy ↓ ↓ ↓');

/**
 * Sets up an `http.Server` or `https.Server` instance with the necessary
 * "request" and "connect" event listeners in order to make the server act as an
 * HTTP proxy.
 *
 * @param {http.Server|https.Server} server
 * @param {Object} options
 * @api public
 */

function setup(server, options) {
	if (!server) server = http.createServer();
	server.on('request', onrequest);
	server.on('connect', onconnect);
	return server;
}

/**
 * sslSites stored all https sites accessed
 */
var sslSites = new Set();
sslSites.add("google.com");
sslSites.add("www.google.com");

var blockSites = new Set();

/**
 * Hop-by-hop headers must be removed by the proxy before passing it on to the
 * next endpoint. Per-request basis hop-by-hop headers MUST be listed in a
 * Connection header, (section 14.10) to be introduced into HTTP/1.1 (or later).
 */

var hopByHopHeaders = [
	'Connection',
	'Keep-Alive',
	'Proxy-Authenticate',
	'Proxy-Authorization',
	'TE',
	'Trailers',
	'Transfer-Encoding',
	'Upgrade',
	'Host'
];

// create a case-insensitive RegExp to match "hop by hop" headers
var isHopByHop = new RegExp('^(' + hopByHopHeaders.join('|') + ')$', 'i');

/**
 * Iterator function for the request/response's "headers".
 * Invokes `fn` for "each" header entry in the request.
 *
 * @api private
 */

function eachHeader(obj, fn) {
	if (Array.isArray(obj.rawHeaders)) {
		// ideal scenario... >= node v0.11.x
		// every even entry is a "key", every odd entry is a "value"
		var key = null;
		obj.rawHeaders.forEach(function (v) {
			if (key === null) {
				key = v;
			} else {
				fn(key, v);
				key = null;
			}
		});
	} else {
		// otherwise we can *only* proxy the header names as lowercase'd
		var headers = obj.headers;
		if (!headers) return;
		Object.keys(headers).forEach(function (key) {
			var value = headers[key];
			if (Array.isArray(value)) {
				// set-cookie
				value.forEach(function (val) {
					fn(key, val);
				});
			} else {
				fn(key, value);
			}
		});
	}
}

// custom `https.Agent` support
var agent = new https.Agent({
	keepAlive: true,
	//maxSockets : 1000,
	maxCachedSessions : 1000
});

/**
 * HTTP GET/POST/DELETE/PUT, etc. proxy requests.
 */

function onrequest(req, res) {
debug(req.url);
	if(req.url.substring(0,1)=='/'){ req.url = 'http://' + req.headers['host']+ req.url ;}
	debug.request('%s %s HTTP/%s ', req.method, req.url, req.httpVersion);
	var server = this;
	var socket = req.socket;
	var parsed = url.parse(req.url);
	//var reqGzip =  req.headers['accept-encoding'] && req.headers['accept-encoding'].toString().includes('gzip') ;

	// proxy the request HTTP method
	parsed.method = req.method;

	// setup outbound proxy request HTTP headers
	var headers = {};
	eachHeader(req, function (key, value) {
		debug.request('Request Header: "%s: %s"', key, value);
		var keyLower = key.toLowerCase();

		if (isHopByHop.test(key)) {
			debug.proxyRequest('ignoring hop-by-hop header "%s"', key);
		} else {
			var v = headers[key];
			if (Array.isArray(v)) {
				v.push(value);
			} else if (null != v) {
				headers[key] = [v, value];
			} else {
				headers[key] = value;
			}
		}
	});
	headers['Accept-Encoding'] = headers['Accept-Encoding'].replace(',br', '').replace(', br', ''); 

	if ('http:' != parsed.protocol) {
		// only "http://" is supported, "https://" should use CONNECT method
		res.writeHead(400);
		res.end('Only "http:" protocol prefix is supported\n');
		return;
	}

	var gotResponse = false;

	var realHost = parsed.host;
	var rurl = req.url.replace('http://', '');
	if(parsed.host.toLowerCase().includes('httpgate.')){
		realHost = parsed.host.replace('httpgate.','');
		rurl = rurl.replace(parsed.host, realHost);
	}
	if(sslSites.has(realHost)) { rurl = 'https.' + rurl;}

	var pr = pRequest(rurl, req.method);
	req.pipe(pr);

	function pRequest(purl,method='GET') {
		var requrl='https://' + flags.domain + '/' + flags.root + '/' + purl;
		var pReq = https.request(requrl, {'agent': agent, 'method': method, 'headers':headers});
		debug.proxyRequest('%s %s HTTP/1.1 ', pReq.method, pReq.path);
		wrapRequest(pReq);
		return pReq;
	}

	function wrapRequest(proxyReq){
		proxyReq.on('response', function (proxyRes) {
			if ([301, 302, 307].includes(proxyRes.statusCode) && proxyRes.headers['location']) {
				location = proxyRes.headers['location'];
				if (location.includes('https')) {
					var sslHost = url.parse(location).host;
					sslSites.add(sslHost);
					debug('Add ssl site: ' + sslHost);
					location = location.replace("https://","https.");
				} else {
					location = location.replace("http://","");
					var sslHost = url.parse(location).host;
					if(sslSites.has(sslHost)) { location = 'https.' + location;}
				}
				pr = pRequest(location);
				pr.end();
				return;
			}

			var resHtml = proxyRes.headers['content-type'] && proxyRes.headers['content-type'].includes('text/html');
			var resGzip =  proxyRes.headers['content-encoding'] && proxyRes.headers['content-encoding'].includes('gzip') ;

			debug.proxyResponse('HTTP/1.1 %s', proxyRes.statusCode);
			gotResponse = true;

			var headers = {};
			eachHeader(proxyRes, function (key, value) {
				debug.proxyResponse(
					'Proxy Response Header: "%s: %s"',
					key,
					value
				);
				if (isHopByHop.test(key)) {
					debug.response('ignoring hop-by-hop header "%s"', key);
				} else {
					var v = headers[key];
					if (Array.isArray(v)) {
						v.push(value);
					} else if (null != v) {
						headers[key] = [v, value];
					} else {
						headers[key] = value;
					}
				}
			});

			debug.response('HTTP/1.1 %s', proxyRes.statusCode);
			res.writeHead(proxyRes.statusCode, headers);
			if (resHtml) {
				debug(req.url + 'piped');
				https2http = new Https2http();
				if(resGzip){
					var gzip = zlib.createGzip();
					var gunzip = zlib.createGunzip();
					proxyRes.pipe(gunzip).pipe(https2http).pipe(gzip).pipe(res);
				} else {
					proxyRes.pipe(https2http).pipe(res);
				}
			} else {
				proxyRes.pipe(res);
			}
			res.on('finish', onfinish);
		});

		proxyReq.on('error', function (err) {
			debug.proxyResponse(
				'proxy HTTP request "error" event\n%s',
				err.stack || err
			);
			cleanup();
			if (gotResponse) {
				debug.response(
					'already sent a response, just destroying the socket...'
				);
				socket.destroy();
			} else if ('ENOTFOUND' == err.code) {
				debug.response('HTTP/1.1 404 Not Found');
				res.writeHead(404);
				res.end();
			} else {
				debug.response('HTTP/1.1 500 Internal Server Error');
				res.writeHead(500);
				res.end();
			}
		});
	}
	
	// if the client closes the connection prematurely,
	// then close the upstream socket
	function onclose() {
		debug.request(
			'client socket "close" event, aborting HTTP request to "%s"',
			req.url
		);
		pr.abort();
		cleanup();
	}
	socket.on('close', onclose);

	function onfinish() {
		debug.response('"finish" event');
		cleanup();
	}

	function cleanup() {
		debug.response('cleanup');
		socket.removeListener('close', onclose);
		res.removeListener('finish', onfinish);
	}

}

/**
 * HTTP CONNECT proxy requests.
 */

function onconnect(req, socket, head) {
	debug.request('%s %s HTTP/%s ', req.method, req.url, req.httpVersion);
	assert(
		!head || 0 == head.length,
		'"head" should be empty for proxy requests'
	);

	var res;

	// define request socket event listeners
	socket.on('close', function onclientclose() {
		debug.request('HTTP request %s socket "close" event', req.url);
	});

	socket.on('end', function onclientend() {
		debug.request('HTTP request %s socket "end" event', req.url);
	});

	socket.on('error', function onclienterror(err) {
		debug.request(
			'HTTP request %s socket "error" event:\n%s',
			req.url,
			err.stack || err
		);
	});

	res = new http.ServerResponse(req);
	res.assignSocket(socket);
	res.writeHead(500);
	res.end();

}

/**
 * Checks `Proxy-Authorization` request headers. Same logic applied to CONNECT
 * requests as well as regular HTTP requests.
 *
 * @param {http.Server} server
 * @param {http.ServerRequest} req
 * @param {Function} fn callback function
 * @api private
 */

function authenticate(server, req, fn) {
	var hasAuthenticate = 'function' == typeof server.authenticate;
	if (hasAuthenticate) {
		debug.request('authenticating request "%s %s"', req.method, req.url);
		server.authenticate(req, fn);
	} else {
		// no `server.authenticate()` function, so just allow the request
		var auth = req.headers['proxy-authorization'];
		fn(null, auth);
	}
}

/**
 * Sends a "407 Proxy Authentication Required" HTTP response to the `socket`.
 *
 * @api private
 */

function requestAuthorization(req, res) {
	// request Basic proxy authorization
	debug.response(
		'requesting proxy authorization for "%s %s"',
		req.method,
		req.url
	);

	// TODO: make "realm" and "type" (Basic) be configurable...
	var realm = 'proxy';

	var headers = {
		'Proxy-Authenticate': 'Basic realm="' + realm + '"'
	};
	res.writeHead(407, headers);
	res.end();
}
