// CloudFront Function (viewer-request) for the site's default behavior.
//
// The S3 origin is reached through Origin Access Control, so it is a REST
// endpoint, not a website endpoint: it serves objects, never a directory's
// index. CloudFront's default_root_object covers "/" only. Without this, every
// "directory" URL the site links or prints returned 404, /trust/ among them.
//
//   /trust/              -> /trust/index.html          (rewritten at the edge)
//   /trust               -> 301 /trust/                (so relative links resolve)
//   /trust/index.html    -> unchanged
//   /.well-known/x.json  -> unchanged                  (anything with an extension)
//   /                    -> unchanged                  (default_root_object)
//   //host, /\\host       -> unchanged                  (never a redirect off-site)
//
// Managed in infrastructure/bootstrap/cloudfront.tf (aws_cloudfront_function.
// directory_index), which reads this file. Tested in tests/test_published_claims.py.
function handler(event) {
  var req = event.request;
  var uri = req.uri;
  if (uri.length > 1 && uri.charAt(uri.length - 1) === '/') {
    req.uri = uri + 'index.html';
    return req;
  }
  // Never redirect a path a browser would read as another host: "//x" and
  // "/\\x" are protocol-relative URLs, so a Location built from them is an open
  // redirect. Such a path is passed through untouched, and S3 answers 404.
  if (/^\/[\/\\]/.test(uri)) {
    return req;
  }
  var last = uri.substring(uri.lastIndexOf('/') + 1);
  if (uri !== '/' && last.indexOf('.') === -1) {
    var qs = [];
    for (var k in req.querystring) {
      var v = req.querystring[k];
      qs.push(encodeURIComponent(k) + (v.value ? '=' + encodeURIComponent(v.value) : ''));
    }
    return {
      statusCode: 301,
      statusDescription: 'Moved Permanently',
      headers: { location: { value: uri + '/' + (qs.length ? '?' + qs.join('&') : '') } },
    };
  }
  return req;
}
