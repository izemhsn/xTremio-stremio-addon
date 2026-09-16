// The one escaping rule the HTML pages depend on. Its own module because both
// page renderers use it and it must never be reimplemented per page: every value
// interpolated into a template literal in this app goes through it, credentials
// and provider-supplied strings alike.

// null and undefined become ''; every other value, 0 and false included, is
// stringified as itself.
function escapeHtml(str) {
    return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

module.exports = { escapeHtml };
