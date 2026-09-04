// Compatibility route for the admin user-management API.
// The main implementation lives in users.js.

export {
  onRequestGet,
  onRequestPost,
  onRequestPatch,
  onRequestDelete
} from "./users.js";
