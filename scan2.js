/**
 * General settings
 */

// strip {{ ... }}, ${ ... } and <% ... %> to make output safe for template systems
// be careful please, this mode is not recommended for production usage.
// allowing template parsing in user-controlled HTML is not advised at all.
// only use this mode if there is really no alternative.
var clean = DOMPurify.sanitize(dirty, {SAFE_FOR_TEMPLATES: true});

/**
 * Control our allow-lists and block-lists
 */
// allow only <b> elements, very strict
var clean = DOMPurify.sanitize(dirty, {ALLOWED_TAGS: ['b']});

// allow only <b> and <q> with style attributes
var clean = DOMPurify.sanitize(dirty, {ALLOWED_TAGS: ['b', 'q'], ALLOWED_ATTR: ['style']});

// allow all safe HTML elements but neither SVG nor MathML
// note that the USE_PROFILES setting will override the ALLOWED_TAGS setting
// so don't use them together
var clean = DOMPurify.sanitize(dirty, {USE_PROFILES: {html: true}});

// allow all safe SVG elements and SVG Filters, no HTML or MathML
var clean = DOMPurify.sanitize(dirty, {USE_PROFILES: {svg: true, svgFilters: true}});

// allow all safe MathML elements and SVG, but no SVG Filters
var clean = DOMPurify.sanitize(dirty, {USE_PROFILES: {mathMl: true, svg: true}});

// change the default namespace from HTML to something different
var clean = DOMPurify.sanitize(dirty, {NAMESPACE: 'http://www.w3.org/2000/svg'});

// leave all safe HTML as it is and add <style> elements to block-list
var clean = DOMPurify.sanitize(dirty, {FORBID_TAGS: ['style']});

// leave all safe HTML as it is and add style attributes to block-list
var clean = DOMPurify.sanitize(dirty, {FORBID_ATTR: ['style']});

// extend the existing array of allowed tags and add <my-tag> to allow-list
var clean = DOMPurify.sanitize(dirty, {ADD_TAGS: ['my-tag']});

// extend the existing array of allowed attributes and add my-attr to allow-list
var clean = DOMPurify.sanitize(dirty, {ADD_ATTR: ['my-attr']});

// prohibit ARIA attributes, leave other safe HTML as is (default is true)
var clean = DOMPurify.sanitize(dirty, {ALLOW_ARIA_ATTR: false});

// prohibit HTML5 data attributes, leave other safe HTML as is (default is true)
var clean = DOMPurify.sanitize(dirty, {ALLOW_DATA_ATTR: false});

/**
 * Control behavior relating to Custom Elements
 */

// DOMPurify allows to define rules for Custom Elements. When using the CUSTOM_ELEMENT_HANDLING
// literal, it is possible to define exactly what elements you wish to allow (by default, none are allowed).
//
// The same goes for their attributes. By default, the built-in or configured allow.list is used.
//
// You can use a RegExp literal to specify what is allowed or a predicate, examples for both can be seen below.
// The default values are very restrictive to prevent accidental XSS bypasses. Handle with great care!


var clean = DOMPurify.sanitize(
    '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
    {
        CUSTOM_ELEMENT_HANDLING: {
            tagNameCheck: null, // no custom elements are allowed
            attributeNameCheck: null, // default / standard attribute allow-list is used
            allowCustomizedBuiltInElements: false, // no customized built-ins allowed
        },
    }
); // <div is=""></div>

var clean = DOMPurify.sanitize(
    '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
    {
        CUSTOM_ELEMENT_HANDLING: {
            tagNameCheck: /^foo-/, // allow all tags starting with "foo-"
            attributeNameCheck: /baz/, // allow all attributes containing "baz"
            allowCustomizedBuiltInElements: true, // customized built-ins are allowed
        },
    }
); // <foo-bar baz="foobar"></foo-bar><div is=""></div>

var clean = DOMPurify.sanitize(
    '<foo-bar baz="foobar" forbidden="true"></foo-bar><div is="foo-baz"></div>',
    {
        CUSTOM_ELEMENT_HANDLING: {
            tagNameCheck: (tagName) => tagName.match(/^foo-/), // allow all tags starting with "foo-"
            attributeNameCheck: (attr) => attr.match(/baz/), // allow all containing "baz"
            allowCustomizedBuiltInElements: true, // allow customized built-ins
        },
    }
); // <foo-bar baz="foobar"></foo-bar><div is="foo-baz"></div>

/**
 * Control behavior relating to URI values
 */
// extend the existing array of elements that can use Data URIs
var clean = DOMPurify.sanitize(dirty, {ADD_DATA_URI_TAGS: ['a', 'area']});

// extend the existing array of elements that are safe for URI-like values (be careful, XSS risk)
var clean = DOMPurify.sanitize(dirty, {ADD_URI_SAFE_ATTR: ['my-attr']});

/**
 * Control permitted attribute values
 */
// allow external protocol handlers in URL attributes (default is false, be careful, XSS risk)
// by default only http, https, ftp, ftps, tel, mailto, callto, cid and xmpp are allowed.
var clean = DOMPurify.sanitize(dirty, {ALLOW_UNKNOWN_PROTOCOLS: true});

// allow specific protocols handlers in URL attributes via regex (default is false, be careful, XSS risk)
// by default only http, https, ftp, ftps, tel, mailto, callto, cid and xmpp are allowed.
// Default RegExp: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;
var clean = DOMPurify.sanitize(dirty, {ALLOWED_URI_REGEXP: /^(?:(?:(?:f|ht)tps?|mailto|tel|callto|cid|xmpp|xxx):|[^a-z]|[a-z+.\-]+(?:[^a-z+.\-:]|$))/i;});

/**
 * Influence the return-type
 */
// return a DOM HTMLBodyElement instead of an HTML string (default is false)
var clean = DOMPurify.sanitize(dirty, {RETURN_DOM: true});

// return a DOM DocumentFragment instead of an HTML string (default is false)
var clean = DOMPurify.sanitize(dirty, {RETURN_DOM_FRAGMENT: true});

// use the RETURN_TRUSTED_TYPE flag to turn on Trusted Types support if available
var clean = DOMPurify.sanitize(dirty, {RETURN_TRUSTED_TYPE: true}); // will return a TrustedHTML object instead of a string if possible

/**
 * Influence how we sanitize
 */
// return entire document including <html> tags (default is false)
var clean = DOMPurify.sanitize(dirty, {WHOLE_DOCUMENT: true});

// disable DOM Clobbering protection on output (default is true, handle with care, minor XSS risks here)
var clean = DOMPurify.sanitize(dirty, {SANITIZE_DOM: false});

// enforce strict DOM Clobbering protection via namespace isolation (default is false)
// when enabled, isolates the namespace of named properties (i.e., `id` and `name` attributes) 
// from JS variables by prefixing them with the string `user-content-` 
var clean = DOMPurify.sanitize(dirty, {SANITIZE_NAMED_PROPS: true});

// keep an element's content when the element is removed (default is true)
var clean = DOMPurify.sanitize(dirty, {KEEP_CONTENT: false});

// glue elements like style, script or others to document.body and prevent unintuitive browser behavior in several edge-cases (default is false)
var clean = DOMPurify.sanitize(dirty, {FORCE_BODY: true});

// remove all <a> elements under <p> elements that are removed
var clean = DOMPurify.sanitize(dirty, {FORBID_CONTENTS: ['a'], FORBID_TAGS: ['p']});

// change the parser type so sanitized data is treated as XML and not as HTML, which is the default
var clean = DOMPurify.sanitize(dirty, {PARSER_MEDIA_TYPE: 'application/xhtml+xml'});

/**
 * Influence where we sanitize
 */
// use the IN_PLACE mode to sanitize a node "in place", which is much faster depending on how you use DOMPurify
var dirty = document.createElement('a');
dirty.setAttribute('href', 'javascript:alert(1)');
var clean = DOMPurify.sanitize(dirty, {IN_PLACE: true}); // see https://github.com/cure53/DOMPurify/issues/288 for more info
