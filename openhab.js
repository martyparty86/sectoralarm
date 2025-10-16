'use strict';

const HttpClient = Java.type('java.net.http.HttpClient');
const HttpRequest = Java.type('java.net.http.HttpRequest');
const HttpResponse = Java.type('java.net.http.HttpResponse');
const URI = Java.type('java.net.URI');
const Duration = Java.type('java.time.Duration');
const CookieHandler = Java.type('java.net.CookieHandler');
const CookieManager = Java.type('java.net.CookieManager');
const CookiePolicy = Java.type('java.net.CookiePolicy');

/**
 * Sector Alarm OAuth 2.0 Authentication Client for OpenHAB
 */
class SectorAlarmClient {
    constructor() {
        this.auth0Domain = "login.sectoralarm.com";
        this.clientId = "keCW6wogC4jMscX1CdZ1WAKmLhcGdlHo";
        this.redirectUri = "https://minasidor.sectoralarm.se/";
        this.audience = "https://minside.sectoralarm.no";
        this.apiEndpoint = "mypagesapi.sectoralarm.net";
        this.sectoralarmsite = "minasidor.sectoralarm.se";
        
        // Generate PKCE parameters for this session
        this.codeVerifier = this.generateCodeVerifier();
        this.codeChallenge = this.generateCodeChallenge(this.codeVerifier);
        this.nonce = this.generateNonce();
        this.state = this.generateState();
        
        this.accessToken = null;
        this.tokenType = 'Bearer';
        
        // Create HTTP client with cookie support and no automatic redirects
        const cookieManager = new CookieManager();
        cookieManager.setCookiePolicy(CookiePolicy.ACCEPT_ALL);
        
        this.httpClient = HttpClient.newBuilder()
            .cookieHandler(cookieManager)
            .followRedirects(HttpClient.Redirect.NEVER)  // Handle redirects manually
            .connectTimeout(Duration.ofSeconds(30))
            .build();
    }

    /**
     * Generate random bytes using Java SecureRandom
     */
    generateRandomBytes(length) {
        const SecureRandom = Java.type('java.security.SecureRandom');
        const random = new SecureRandom();
        const bytes = [];
        for (let i = 0; i < length; i++) {
            bytes.push(random.nextInt(256) - 128); // Generate signed byte values (-128 to 127)
        }
        return bytes;
    }

    /**
     * Convert bytes to base64url encoding
     */
    bytesToBase64Url(bytes) {
        // Convert JavaScript array to Java byte array
        const ByteArray = Java.type('byte[]');
        const javaBytes = new ByteArray(bytes.length);
        for (let i = 0; i < bytes.length; i++) {
            javaBytes[i] = bytes[i];
        }
        
        const Base64 = Java.type('java.util.Base64');
        const base64 = Base64.getEncoder().encodeToString(javaBytes);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }

    /**
     * Generate PKCE code verifier (RFC 7636) - OpenHAB version
     */
    generateCodeVerifier() {
        const bytes = this.generateRandomBytes(32);
        return this.bytesToBase64Url(bytes);
    }

    /**
     * Generate PKCE code challenge from verifier - OpenHAB version
     */
    generateCodeChallenge(verifier) {
        const MessageDigest = Java.type('java.security.MessageDigest');
        const digest = MessageDigest.getInstance('SHA-256');
        
        // Convert JavaScript string to Java string and get bytes
        const JavaString = Java.type('java.lang.String');
        const javaString = new JavaString(verifier);
        const bytes = javaString.getBytes('UTF-8');
        const hash = digest.digest(bytes);
        
        // Convert Java byte array to JavaScript array
        const hashArray = [];
        for (let i = 0; i < hash.length; i++) {
            hashArray.push(hash[i]);
        }
        
        return this.bytesToBase64Url(hashArray);
    }

    /**
     * Generate random nonce for OAuth request - OpenHAB version
     */
    generateNonce() {
        const bytes = this.generateRandomBytes(16);
        return this.bytesToBase64Url(bytes);
    }

    /**
     * Generate random state for OAuth request - OpenHAB version
     */
    generateState() {
        const bytes = this.generateRandomBytes(16);
        return this.bytesToBase64Url(bytes);
    }

    /**
     * Parse cookies from Set-Cookie headers
     */
    parseCookies(setCookieHeaders) {
        if (!setCookieHeaders) return [];
        return setCookieHeaders.split('\n').map(cookie => {
            return cookie.split(';')[0].trim();
        }).filter(cookie => cookie.length > 0);
    }

    /**
     * Build URL query string from parameters object
     */
    buildQueryString(params) {
        const pairs = [];
        for (const key in params) {
            if (params.hasOwnProperty(key)) {
                pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
            }
        }
        return pairs.join('&');
    }

    /**
     * Build form data string from parameters object
     */
    buildFormData(params) {
        const pairs = [];
        for (const key in params) {
            if (params.hasOwnProperty(key)) {
                pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(params[key]));
            }
        }
        return pairs.join('&');
    }

    /**
     * Helper method to perform HTTP GET request
     */
    async httpGet(url, headers = {}) {
        const requestBuilder = HttpRequest.newBuilder()
            .GET()
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(30));
            
        // Add headers
        for (const [key, value] of Object.entries(headers)) {
            requestBuilder.header(key, value);
        }
        
        const request = requestBuilder.build();
        const response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        return {
            statusCode: response.statusCode(),
            body: response.body(),
            headers: response.headers().map()
        };
    }

    /**
     * Helper method to perform HTTP POST request
     */
    async httpPost(url, body, contentType, headers = {}) {
        const requestBuilder = HttpRequest.newBuilder()
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .uri(URI.create(url))
            .timeout(Duration.ofSeconds(30))
            .header('Content-Type', contentType);
            
        // Add additional headers
        for (const [key, value] of Object.entries(headers)) {
            requestBuilder.header(key, value);
        }
        
        const request = requestBuilder.build();
        const response = this.httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        
        return {
            statusCode: response.statusCode(),
            body: response.body(),
            headers: response.headers().map()
        };
    }


    /**
     * Main authentication method
     */
    async authenticate(email, password) {
        const oauthData = await this.getOAuthState();
        const formData = await this.getLoginForm(oauthData.state, oauthData.cookies);
        const loginResult = await this.performLogin(email, password, formData.hiddenState, formData.cookies);
      
        if (loginResult.success && loginResult.authorizationCode) {
            const tokenData = await this.exchangeCodeForToken(loginResult.authorizationCode);
            
            // Store the access token (strip any "Bearer " prefix if present)
            let accessToken = tokenData.access_token;
            if (accessToken && accessToken.startsWith('Bearer ')) {
                accessToken = accessToken.substring(7);
            }
            
            this.accessToken = accessToken;
            this.tokenType = '';
            
            return {
                accessToken: this.accessToken,
                tokenType: this.tokenType,
                expiresIn: tokenData.expires_in,
                scope: tokenData.scope,
                idToken: tokenData.id_token
            };
        } else {
            throw new Error('OAuth authentication failed - no authorization code');
        }
    }

    /**
     * Step 1: Initiate OAuth flow to get fresh state parameter
     */
    async getOAuthState() {
        const params = {
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            audience: this.audience,
            response_type: 'code',
            scope: 'openid profile email',
            grant_type: 'client_credentials',
            language: 'sv',
            response_mode: 'query',
            state: this.state,
            nonce: this.nonce,
            code_challenge: this.codeChallenge,
            code_challenge_method: 'S256',
            auth0Client: 'eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuNiJ9'
        };

        const url = `https://${this.auth0Domain}/authorize?${this.buildQueryString(params)}`;
        const headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://minasidor.sectoralarm.se/',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-User': '?1'
        };

        try {
            const response = await this.httpGet(url, headers);
            
            // Extract cookies from Set-Cookie headers
            const setCookieHeaders = response.headers.get('set-cookie');
            let cookies = [];
            if (setCookieHeaders && setCookieHeaders.length > 0) {
                const cookieStrings = [];
                for (let i = 0; i < setCookieHeaders.length; i++) {
                    cookieStrings.push(setCookieHeaders[i]);
                }
                cookies = this.parseCookies(cookieStrings.join('\n'));
            }
            
            // Check if this is a redirect (302/301)
            if (response.statusCode >= 300 && response.statusCode < 400) {
                const locationHeader = response.headers.get('location');
                if (locationHeader && locationHeader.length > 0) {
                    let redirectUrl = locationHeader[0];
                    if (redirectUrl.startsWith('/')) {
                        redirectUrl = `https://${this.auth0Domain}${redirectUrl}`;
                    }
                    
                    const stateMatch = redirectUrl.match(/[?&]state=([^&"'#\s]+)/);
                    if (stateMatch) {
                        return {
                            state: stateMatch[1],
                            cookies: cookies
                        };
                    }
                }
            }
            
            return {
                state: this.state,
                cookies: cookies
            };
            
        } catch (error) {
            return {
                state: this.state,
                cookies: []
            };
        }
    }


    /**
     * Step 2: Get the Auth0 login form and extract hidden state
     */
    async getLoginForm(state, initialCookies) {
        const url = `https://${this.auth0Domain}/u/login?state=${encodeURIComponent(state)}`;
        
        // Convert cookies array to string for Cookie header
        let cookieString = '';
        if (initialCookies && initialCookies.length > 0) {
            cookieString = initialCookies.join('; ');
        }
        
        const headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Cookie': cookieString,
            'Referer': 'https://minasidor.sectoralarm.se/',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'cross-site',
            'Sec-Fetch-User': '?1'
        };

        const response = await this.httpGet(url, headers);
        
        // Extract new cookies from response
        const setCookieHeaders = response.headers.get('set-cookie');
        let newCookies = [];
        if (setCookieHeaders && setCookieHeaders.length > 0) {
            const cookieStrings = [];
            for (let i = 0; i < setCookieHeaders.length; i++) {
                cookieStrings.push(setCookieHeaders[i]);
            }
            newCookies = this.parseCookies(cookieStrings.join('\n'));
        }
        
        const allCookies = [...initialCookies, ...newCookies];
        
        // Extract the hidden state value from the form
        const hiddenStateMatch = response.body.match(/name="state"\s+value="([^"]+)"/);
        
        return {
            cookies: allCookies,
            hiddenState: hiddenStateMatch ? hiddenStateMatch[1] : state
        };
    }

    /**
     * Step 3: Perform login with credentials
     */
    async performLogin(email, password, hiddenState, cookies) {
        const formData = {
            state: hiddenState,
            username: email,
            password: password
        };

        const url = `https://${this.auth0Domain}/u/login`;
        
        // Convert cookies array to string for Cookie header
        let cookieString = '';
        if (cookies && cookies.length > 0) {
            cookieString = cookies.join('; ');
        }
        
        const headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Cookie': cookieString,
            'Origin': `https://${this.auth0Domain}`,
            'Referer': `https://${this.auth0Domain}/u/login?state=${encodeURIComponent(hiddenState)}`,
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1',
            'TE': 'trailers'
        };

        const formDataString = this.buildFormData(formData);
        
        try {
            const response = await this.httpPost(url, formDataString, 'application/x-www-form-urlencoded', headers);
            
            // Handle redirects to find authorization code
            if (response.statusCode >= 300 && response.statusCode < 400) {
                const locationHeader = response.headers.get('location');
                if (locationHeader && locationHeader.length > 0) {
                    let redirectUrl = locationHeader[0];
                    if (redirectUrl.startsWith('/')) {
                        redirectUrl = `https://${this.auth0Domain}${redirectUrl}`;
                    }
                    return await this.followRedirectForCode(redirectUrl, cookies, 0);
                }
            }
            
            const responseBody = response.body;
            
            // Check for Auth0 error messages
            if (responseBody.includes('Wrong email or password') || 
                responseBody.includes('WrongUsernamePasswordError')) {
                throw new Error('Login failed: Wrong email or password');
            }
            
            if (responseBody.includes('unhandled-error-cont') || responseBody.includes('something went wrong')) {
                const trackingIdMatch = responseBody.match(/TRACKING ID:\s*<\/span><span[^>]*>([^<]+)</);
                let errorMessage = 'Auth0 server error';
                if (trackingIdMatch) {
                    errorMessage += ` (Tracking ID: ${trackingIdMatch[1].trim()})`;
                }
                throw new Error(`Login failed: ${errorMessage}`);
            }
            
            throw new Error('Login failed - unexpected response format');
            
        } catch (error) {
            if (error.message.includes('Login failed:')) {
                throw error;
            }
            throw new Error(`Login request error: ${error.message}`);
        }
    }

    /**
     * Follow redirects to find authorization code
     */
    async followRedirectForCode(url, cookies, depth) {
        if (depth > 5) {
            throw new Error('Too many redirects');
        }
        
        // Convert cookies array to string for Cookie header
        let cookieString = '';
        if (cookies && cookies.length > 0) {
            cookieString = cookies.join('; ');
        }
        
        const headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Cookie': cookieString,
            'Referer': `https://${this.auth0Domain}/u/login`,
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Fetch-User': '?1'
        };
        
        const response = await this.httpGet(url, headers);
        
        // Check if this redirect URL contains the code
        const codeMatch = url.match(/[?&]code=([^&"'#\s]+)/);
        if (codeMatch) {
            return {
                success: true,
                authorizationCode: codeMatch[1]
            };
        }
        
        // Check for another redirect
        if (response.statusCode >= 300 && response.statusCode < 400) {
            const locationHeader = response.headers.get('location');
            if (locationHeader && locationHeader.length > 0) {
                let nextRedirectUrl = locationHeader[0];
                if (nextRedirectUrl.startsWith('/')) {
                    nextRedirectUrl = `https://${this.auth0Domain}${nextRedirectUrl}`;
                }
                return await this.followRedirectForCode(nextRedirectUrl, cookies, depth + 1);
            }
        }
        
        throw new Error('No authorization code found after following redirects');
    }

    /**
     * Step 4: Exchange authorization code for access token using PKCE
     */
    async exchangeCodeForToken(authorizationCode) {
        const tokenData = {
            client_id: this.clientId,
            code_verifier: this.codeVerifier,
            grant_type: 'authorization_code',
            code: authorizationCode,
            redirect_uri: this.redirectUri
        };
        
        const url = `https://${this.auth0Domain}/oauth/token`;
        const headers = {
            'Auth0-Client': 'eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjIuNiJ9',
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Origin': 'https://minasidor.sectoralarm.se',
            'Referer': 'https://minasidor.sectoralarm.se/',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'cross-site',
            'TE': 'trailers'
        };
        
        const jsonString = JSON.stringify(tokenData);
        const response = await this.httpPost(url, jsonString, 'application/json', headers);
        
        try {
            return JSON.parse(response.body);
        } catch (e) {
            throw new Error(`Invalid token response format: ${response.body.substring(0, 200)}`);
        }
    }

    /**
     * Get site status after authentication
     */
    async getStatus(siteId) {
        if (!this.accessToken) {
            throw new Error('No access token available. Please authenticate first.');
        }

        const url = `https://${this.apiEndpoint}/api/Panel/GetPanelStatus?panelId=${siteId}`;
        const headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Authorization': this.accessToken,
            'Platform': 'mypage_web',
            'Version': '2.41.0',
            'Origin': `https://${this.sectoralarmsite}`,
            'Referer': `https://${this.sectoralarmsite}/`,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        };

        const response = await this.httpGet(url, headers);
        return JSON.parse(response.body);
    }

    /**
     * Get site information after authentication
     */
    async getInfo(siteId) {
        if (!this.accessToken) {
            throw new Error('No access token available. Please authenticate first.');
        }

        const url = `https://${this.apiEndpoint}/api/Panel/GetPanel?panelId=${siteId}`;
        const headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Authorization': this.accessToken,
            'Platform': 'mypage_web',
            'Version': '2.41.0',
            'Origin': `https://${this.sectoralarmsite}`,
            'Referer': `https://${this.sectoralarmsite}/`,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        };

        const response = await this.httpGet(url, headers);
        return JSON.parse(response.body);
    }

    /**
     * Get site history/logs after authentication
     */
    async getHistory(siteId) {
        if (!this.accessToken) {
            throw new Error('No access token available. Please authenticate first.');
        }

        const url = `https://${this.apiEndpoint}/api/Panel/GetLogs?panelId=${siteId}`;
        const headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Authorization': this.accessToken,
            'Platform': 'mypage_web',
            'Version': '2.41.0',
            'Origin': `https://${this.sectoralarmsite}`,
            'Referer': `https://${this.sectoralarmsite}/`,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        };

        const response = await this.httpGet(url, headers);
        return JSON.parse(response.body);
    }

    /**
     * Arm the alarm system
     */
    async arm(siteId, code) {
        if (!this.accessToken) {
            throw new Error('No access token available. Please authenticate first.');
        }

        const payload = JSON.stringify({
            "PanelCode": code,
            "PanelId": siteId
        });

        const url = `https://${this.apiEndpoint}/api/Panel/Arm`;
        const headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Authorization': this.accessToken,
            'Platform': 'mypage_web',
            'Version': '2.41.0',
            'Origin': `https://${this.sectoralarmsite}`,
            'Referer': `https://${this.sectoralarmsite}/`,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        };

        const response = await this.httpPost(url, payload, 'application/json', headers);
        return JSON.parse(response.body);
    }

    /**
     * Disarm the alarm system
     */
    async disarm(siteId, code) {
        if (!this.accessToken) {
            throw new Error('No access token available. Please authenticate first.');
        }

        const payload = JSON.stringify({
            "PanelCode": code,
            "PanelId": siteId
        });

        const url = `https://${this.apiEndpoint}/api/Panel/Disarm`;
        const headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Authorization': this.accessToken,
            'Platform': 'mypage_web',
            'Version': '2.41.0',
            'Origin': `https://${this.sectoralarmsite}`,
            'Referer': `https://${this.sectoralarmsite}/`,
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
        };

        const response = await this.httpPost(url, payload, 'application/json', headers);
        return JSON.parse(response.body);
    }
}

// Example usage for OpenHAB:
// const client = new SectorAlarmClient();
// await client.authenticate('your-email@example.com', 'your-password');
// const status = await client.getStatus('your-site-id');
// const info = await client.getInfo('your-site-id');
// const history = await client.getHistory('your-site-id');
// await client.arm('your-site-id', 'your-code');
// await client.disarm('your-site-id', 'your-code');
