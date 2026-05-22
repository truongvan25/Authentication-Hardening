// Sets a flag so the proxy entry point knows to rewrite this response.
// Actual rewriting happens in the onProxyRes hook in index.js because
// http-proxy-middleware intercepts the stream before Express can.
module.exports = function normalizeResp(req, _res, next) {
  req._normalize = true;
  next();
};
