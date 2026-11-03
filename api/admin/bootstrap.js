// Explicit Vercel route for the one-time first-admin bootstrap endpoint.
// Reuse the shared API handler so validation, hashing, session creation and audit logging stay consistent.
module.exports = require("../[...path].js");
