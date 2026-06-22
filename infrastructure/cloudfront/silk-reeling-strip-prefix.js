// CloudFront Function (viewer-request) for the /silk-reeling/* behavior.
//
// Strips the /silk-reeling prefix before the request reaches the API Gateway
// origin, so the app's own routes match: it serves the SPA at "/" and the
// API at "/analyze", "/exercises", etc. The frontend is built with
// base=/silk-reeling/ and VITE_API_BASE=/silk-reeling, so every viewer request
// comes in under /silk-reeling/... and leaves this function as /...
//
//   /silk-reeling            -> /
//   /silk-reeling/            -> /
//   /silk-reeling/api/analyze -> /api/analyze
//   /silk-reeling/assets/x    -> /assets/x
//
// The Authorization header (the Cognito JWT Bearer token) is preserved — forward
// it via the AllViewerExceptHostHeader origin-request policy on the behavior so
// the API Gateway's Cognito JWT authorizer on /api/* can validate it (Task 3).
function handler(event) {
  var req = event.request;
  var uri = req.uri;
  if (uri === '/silk-reeling' || uri === '/silk-reeling/') {
    req.uri = '/';
  } else if (uri.startsWith('/silk-reeling/')) {
    req.uri = uri.substring('/silk-reeling'.length);
  }
  return req;
}
