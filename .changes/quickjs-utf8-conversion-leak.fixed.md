Converting a JavaScript string to UTF-8 no longer leaks the string when its copy can't be allocated, for example when `ccf.strToBuf`, `console.log` or an endpoint's response body hits the runtime's heap limit.
Before, the string stayed allocated even after its interpreter was freed.
