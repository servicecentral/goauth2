GOAuth2
=======
A comprehensive PHP wrapper for the OAuth 2.0 specification (based on [v15 of the IETF draft specification](http://tools.ietf.org/html/draft-ietf-oauth-v2-15)). It includes both servers (including Authorization and Token endpoints) and a client, and features:

* Support for both bearer and signed MAC tokens (currently based on [v3 of the IETF draft specification](http://tools.ietf.org/html/draft-hammer-oauth-v2-mac-token-03))
* Support for 2-legged authentication (client credential flow)
* Support for 3-legged authentication (both resource owner credentials and authorization code flow)
* A <tt>call()</tt> client method that automatically signs API requests using an access token  
* Variable scopes, enforced SSL, refresh tokens, variable client authentication methods


Usage
-------
Example servers using MongoDB are currently in the works and will be available shortly, followed by client implementations for some common OAuth 2.0 usage (eg Facebook).


Resources
---------
* View Source on GitHub (https://github.com/servicecentral/goauth2)
* Report Issues on GitHub (https://github.com/servicecentral/goauth2/issues)


Copyright and License
---------
Copyright (c) 2011 Service Central

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.