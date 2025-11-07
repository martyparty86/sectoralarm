'use strict'

var https = require('https');
var Promise = require('promise');
var crypto = require('crypto');
var zlib = require('zlib');
var SectorAlarmError = require('./sectoralarmerror.js');

/**
 * OAuth2Client for Sector Alarm Authentication
 * 
 * This class handles the complete OAuth 2.0 authentication flow with Auth0
 * as used by Sector Alarm's authentication system.
 * 
 * Flow: OAuth Authorize → Login Form → Login POST → Authorization Code → Token Exchange → API Access
 */
class OAuth2Client {
    constructor(settings) {
        this._auth0Domain = "login.sectoralarm.com";
        this._clientId = "keCW6wogC4jMscX1CdZ1WAKmLhcGdlHo";
        this._redirectUri = "https://minasidor.sectoralarm.se/";
        this._audience = "https://minside.sectoralarm.no";
        this._settings = settings;
        
        // Generate PKCE parameters for this session
        this._codeVerifier = this._generateCodeVerifier();
        this._codeChallenge = this._generateCodeChallenge(this._codeVerifier);
        this._nonce = this._generateNonce();
        this._state = this._generateState();
    }

    snooze = ms => new Promise(resolve => setTimeout(resolve, ms));

    /**
     * Generate PKCE code verifier (RFC 7636)
     * @private
     */
    _generateCodeVerifier() {
        return crypto.randomBytes(32).toString('base64url');
    }

    /**
     * Generate PKCE code challenge from verifier
     * @private
     */
    _generateCodeChallenge(verifier) {
        return crypto.createHash('sha256').update(verifier).digest('base64url');
    }

    /**
     * Generate random nonce for OAuth request
     * @private
     */
    _generateNonce() {
        return crypto.randomBytes(16).toString('base64url');
    }

    /**
     * Generate random state for OAuth request
     * @private
     */
    _generateState() {
        return crypto.randomBytes(16).toString('base64url');
    }

    /**
     * Parse cookies properly by extracting only name=value pairs
     * @private
     */
    _parseCookies(setCookieHeaders) {
        return setCookieHeaders.map(cookie => {
            // Extract just the name=value part, ignore attributes
            return cookie.split(';')[0].trim();
        });
    }

    /**
     * Complete OAuth 2.0 authentication flow with PKCE
     * @param {string} email - User's email address
     * @param {string} password - User's password
     * @returns {Promise} Promise resolving to token data
     */
    authenticate(email, password) {
        var client = this;
        
        return this._getOAuthState()
            .then(oauthData => {
                return client._getLoginForm(oauthData.state, oauthData.cookies);
            })
            .then(formData => {
                return client._performLogin(email, password, formData.hiddenState, formData.cookies);
            })
            .then(loginResult => {
                if (loginResult.success && loginResult.authorizationCode) {
                    // Exchange authorization code for access token using PKCE
                    return client._exchangeCodeForToken(loginResult.authorizationCode);
                } else {
                    throw new SectorAlarmError('ERR_INVALID_CREDENTIALS', 'OAuth authentication failed');
                }
            })
            .then(tokenData => {
                return {
                    accessToken: tokenData.access_token,
                    tokenType: tokenData.token_type || 'Bearer',
                    expiresIn: tokenData.expires_in,
                    scope: tokenData.scope,
                    idToken: tokenData.id_token
                };
            });
    }

    /**
     * Step 1: Initiate OAuth flow to get fresh state parameter
     * @private
     */
    _getOAuthState() {
        var client = this;
        
        // Build OAuth authorize URL with all required parameters (matching browser exactly)
        const params = new URLSearchParams({
            client_id: this._clientId,
            redirect_uri: this._redirectUri,
            audience: this._audience,
            response_type: 'code',
            scope: 'openid profile email',
            grant_type: 'client_credentials',
            language: 'sv',
            response_mode: 'query',
            state: this._state,
            nonce: this._nonce,
            code_challenge: this._codeChallenge,
            code_challenge_method: 'S256',
            auth0Client: 'eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuNiJ9'
        });
        
        var options = {
            host: this._auth0Domain,
            port: 443,
            path: `/authorize?${params.toString()}`,
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Connection': 'keep-alive',
                'Referer': 'https://minasidor.sectoralarm.se/',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-User': '?1'
            }
        };

        return new Promise(function(resolve, reject) {
            var request = https.request(options, function(response) {
                if (response.statusCode === 302 && response.headers.location) {
                    const stateMatch = response.headers.location.match(/[?&]state=([^&]+)/);
                    if (stateMatch) {
                        resolve({
                            state: stateMatch[1],
                            cookies: client._parseCookies(response.headers['set-cookie'] || [])
                        });
                    } else {
                        reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'No state parameter in OAuth redirect'));
                    }
                } else {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `OAuth authorize failed with status: ${response.statusCode}`));
                }
            });

            request.on('error', function(e) {
                reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'OAuth authorize request failed', e));
            });

            request.end();
        });
    }

    /**
     * Step 2: Get the Auth0 login form and extract hidden state
     * @private
     */
    _getLoginForm(state, initialCookies) {
        var client = this;
        
        var options = {
            host: this._auth0Domain,
            port: 443,
            path: `/u/login?state=${encodeURIComponent(state)}`,
            method: 'GET',
            headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Connection': 'keep-alive',
                'Cookie': initialCookies.join('; '),
                'Referer': 'https://minasidor.sectoralarm.se/',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'cross-site',
                'Sec-Fetch-User': '?1'
            }
        };

        return new Promise(function(resolve, reject) {
            var content = '';
            var request = https.request(options, function(response) {
                if (response.statusCode !== 200) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `Login form request failed with status: ${response.statusCode}`));
                    return;
                }

                response.setEncoding("utf8");
                response.on("data", function (chunk) {
                    content += chunk;
                });
                
                response.on("end", function () {
                    const newCookies = client._parseCookies(response.headers['set-cookie'] || []);
                    const allCookies = [...initialCookies, ...newCookies];
                    
                    // Extract the hidden state value from the form
                    const hiddenStateMatch = content.match(/name="state"\s+value="([^"]+)"/);
                    
                    resolve({
                        cookies: allCookies,
                        hiddenState: hiddenStateMatch ? hiddenStateMatch[1] : state
                    });
                });
            });

            request.on('error', function(e) {
                reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Login form request failed', e));
            });

            request.end();
        });
    }

    /**
     * Step 3: Perform login with credentials
     * @private
     */
    _performLogin(email, password, hiddenState, cookies) {
        var client = this;
        
        const formData = new URLSearchParams();
        formData.append('state', hiddenState);
        formData.append('username', email);
        formData.append('password', password);

        const formDataString = formData.toString();

        var options = {
            host: this._auth0Domain,
            port: 443,
            path: '/u/login',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Content-Length': Buffer.byteLength(formDataString),
                'Cookie': cookies.join('; '),
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Origin': `https://${this._auth0Domain}`,
                'Connection': 'keep-alive',
                'Referer': `https://${this._auth0Domain}/u/login?state=${encodeURIComponent(hiddenState)}`,
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1',
                'TE': 'trailers'
            }
        };

        return new Promise(function(resolve, reject) {
            var request = https.request(options, function(response) {
                // Handle redirects (successful login)
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    return client._handleLoginRedirect(response.headers.location, cookies)
                        .then(resolve)
                        .catch(reject);
                }
                
                // Handle login failure
                var content = '';
                response.setEncoding("utf8");
                response.on("data", function (chunk) {
                    content += chunk;
                });
                
                response.on("end", function () {
                    // Check for specific error messages
                    if (content.includes('Wrong email or password') || 
                        content.includes('Invalid credentials') ||
                        content.includes('Please enter an email address') ||
                        content.includes('Password is required')) {
                        reject(new SectorAlarmError('ERR_INVALID_CREDENTIALS', 'Invalid login credentials'));
                    } else {
                        reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `Login failed with status: ${response.statusCode}`));
                    }
                });
            });

            request.on('error', function(e) {
                reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Login request failed', e));
            });

            request.write(formDataString);
            request.end();
        });
    }

    /**
     * Step 4: Handle login redirect and extract authorization code
     * @private
     */
    _handleLoginRedirect(location, cookies) {
        var client = this;
        
        // Check if this is the final redirect with authorization code
        const codeMatch = location.match(/[?&]code=([^&]+)/);
        if (codeMatch) {
            return Promise.resolve({
                success: true,
                authorizationCode: codeMatch[1],
                location: location
            });
        }
        
        // Follow intermediate redirects (like /authorize/resume)
        if (location.startsWith('/')) {
            location = `https://${this._auth0Domain}${location}`;
        }
        
        const url = new URL(location);
        
        var options = {
            host: url.hostname,
            port: 443,
            path: url.pathname + url.search,
            method: 'GET',
            headers: {
                'Cookie': cookies.join('; '),
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Referer': `https://${this._auth0Domain}/u/login`,
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Sec-Fetch-User': '?1'
            }
        };

        return new Promise(function(resolve, reject) {
            var request = https.request(options, function(response) {
                if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                    // Follow the next redirect
                    return client._handleLoginRedirect(response.headers.location, cookies)
                        .then(resolve)
                        .catch(reject);
                } else {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `Redirect handling failed with status: ${response.statusCode}`));
                }
            });

            request.on('error', function(e) {
                reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Redirect request failed', e));
            });

            request.end();
        });
    }

    /**
     * Step 4: Exchange authorization code for access token using PKCE
     * @private
     */
    _exchangeCodeForToken(authorizationCode) {
        var client = this;
        
        const tokenData = {
            client_id: this._clientId,
            code_verifier: this._codeVerifier,
            grant_type: 'authorization_code',
            code: authorizationCode,
            redirect_uri: this._redirectUri
        };
        
        const payload = JSON.stringify(tokenData);
        
        var options = {
            host: this._auth0Domain,
            port: 443,
            path: '/oauth/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'Auth0-Client': 'eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuNiJ9',
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Accept': '*/*',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Origin': 'https://minasidor.sectoralarm.se',
                'Connection': 'keep-alive',
                'Referer': 'https://minasidor.sectoralarm.se/',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'cross-site',
                'TE': 'trailers'
            }
        };
        
        return new Promise(function(resolve, reject) {
            var request = https.request(options, function(response) {
                var chunks = [];
                
                // Handle compressed responses
                var stream = response;
                if (response.headers['content-encoding'] === 'gzip') {
                    stream = zlib.createGunzip();
                    response.pipe(stream);
                } else if (response.headers['content-encoding'] === 'deflate') {
                    stream = zlib.createInflate();
                    response.pipe(stream);
                } else if (response.headers['content-encoding'] === 'br') {
                    stream = zlib.createBrotliDecompress();
                    response.pipe(stream);
                }
                
                stream.on("data", function (chunk) {
                    chunks.push(chunk);
                });
                
                stream.on("end", function () {
                    const content = Buffer.concat(chunks).toString('utf8');
                    
                    if (response.statusCode === 200) {
                        try {
                            const tokenResponse = JSON.parse(content);
                            resolve(tokenResponse);
                        } catch (e) {
                            reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `Invalid token response format. Content: ${content.substring(0, 200)}`, e));
                        }
                    } else {
                        reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', `Token exchange failed with status: ${response.statusCode}. Response: ${content}`));
                    }
                });
                
                stream.on('error', function(e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Response decompression failed', e));
                });
            });
            
            request.on('error', function(e) {
                reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Token exchange request failed', e));
            });
            
            request.write(payload);
            request.end();
        });
    }
}

module.exports = OAuth2Client;
