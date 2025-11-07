'use strict'

var https = require('https');
var Promise = require('promise');
var SectorAlarmError = require('./sectoralarmerror.js');
var OAuth2Client = require('./oauth2client.js');

class Client {
    constructor(settings) {
        this._sectoralarmsite = "minasidor.sectoralarm.se";
        this._apiEndpoint = "mypagesapi.sectoralarm.net";
        this._settings = settings;
        this._oauth2Client = new OAuth2Client(settings);
        this._accessToken = null;
        this._tokenType = 'Bearer';
    }

    snooze = ms => new Promise(resolve => setTimeout(resolve, ms));

    authenticate(email, password) {
        var client = this;
        
        return this._oauth2Client.authenticate(email, password)
            .then(tokenData => {
                client._accessToken = tokenData.accessToken;
                client._tokenType = tokenData.tokenType;
                return tokenData;
            });
    }

    _extractVersion(content) {
        var startPosition = content.search("/Scripts/main.js?");
        var modifiedContent = content.slice(startPosition+17);
        var endPosition = modifiedContent.search("\"");
        var version = modifiedContent.slice(0, endPosition);
        return version;
    }

    /**
     * Legacy login method - now redirects to OAuth2 authentication
     * @deprecated Use authenticate() instead
     */
    login(email, password, cookies) {
        console.warn('login() is deprecated. Use authenticate() instead.');
        return this.authenticate(email, password);
    }

    getStatus(siteId, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: `/api/Panel/GetPanelStatus?panelId=${siteId}`,
            method: 'GET',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }
            
            const requestWithRetry = (siteId, retry) => {

                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {
                        resolve(content);
                    });
                });
                
                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.end();
            }

            return requestWithRetry(siteId, retry);

        });
    }

    getInfo(siteId, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: `/api/Panel/GetPanel?panelId=${siteId}`,
            method: 'GET',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }
            
            const requestWithRetry = (siteId, retry) => {

                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {
                        resolve(content);
                    });
                });
                
                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.end();
            }

            return requestWithRetry(siteId, retry);

        });
    }

    getLocks(siteId, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: '/Locks/GetLocks/?WithStatus=true&id=' + siteId,
            method: 'GET',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }

            const requestWithRetry = (siteId, retry) => {
                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    if (response.statusCode == 500) {
                        // In the case of locks, when trying to get it for some reason Sector alarm sends out a 500 if you don't have any locks
                        resolve(JSON.stringify([]));
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {
                        resolve(content);
                    });
                });

                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.end();
            }
            return requestWithRetry(siteId, retry);
        });
    }

    getHistory(siteId, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: `/api/Panel/GetLogs?panelId=${siteId}`,
            method: 'GET',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }
            
            const requestWithRetry = (siteId, retry) => {
                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {
                        if (content.indexOf("<!DOCTYPE html>")>0) {
                            reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. This error is often due to problems on sector alarm servers. No additional information'));
                        }
                        resolve(content);
                    });
                });

                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.end();
            }

            return requestWithRetry(siteId, retry);
        });
    }

    getTemperatures(siteId, retry = this._settings.numberOfRetries) {
        var client = this;
        var payload = JSON.stringify({
            "id": siteId
        });

        var content = '';

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: '/Panel/GetTempratures/',
            method: 'POST',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }

            const requestWithRetry = (siteId, retry) => {

                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {

                        if (content.indexOf("<!DOCTYPE html>")>0) {
                            reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. This error is often due to problems on sector alarm servers. No additional information'));
                        }

                        resolve(content);
                    });
                });

                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.write(payload);
                request.end();
            }

            return requestWithRetry(siteId, retry)
        });
    }

    act(siteId, code, command, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';

        // Map command to correct endpoint path
        var endpointPath;
        if (command === 'Total' || command === 'Arm') {
            endpointPath = '/api/Panel/Arm';
        } else if (command === 'Partial') {
            endpointPath = '/api/Panel/PartialArm';
        } else if (command === 'Disarm') {
            endpointPath = '/api/Panel/Disarm';
        } else if (command === 'AnnexArm') {
            endpointPath = '/api/Panel/AnnexArm';
        } else if (command === 'AnnexPartial') {
            endpointPath = '/api/Panel/AnnexPartialArm';
        } else if (command === 'AnnexDisarm') {
            endpointPath = '/api/Panel/AnnexDisarm';
        } else {
            endpointPath = '/api/Panel/Arm'; // fallback
        }

        var payload = JSON.stringify({
            "PanelCode": code,
            "PanelId": siteId
        });

        var options = {
            host: this._apiEndpoint,
            port: 443,
            path: endpointPath,
            method: 'POST',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {

            if (command != 'Disarm' && command != 'Total' && command != 'Partial' && command != 'ArmAnnex' && command != 'DisarmAnnex') {
                reject(new SectorAlarmError('ERR_INVALID_COMMAND','Invalid command sent to act on site. Should be Disarm, Total, Partial, ArmAnnex or DisarmAnnex'));
                return;
            }

            const requestWithRetry = (siteId, code, command, retry) => {

                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, code, command, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {

                        if (content.indexOf("<!DOCTYPE html>")>0) {
                            reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. This error is often due to problems on sector alarm servers. No additional information'));
                        }

                        resolve(content);
                    });
                });

                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.write(payload);
                request.end();
            }

            return requestWithRetry(siteId, code, command, retry);
        });
    }

    actOnLock(siteId, lockId, code, command, retry = this._settings.numberOfRetries) {
        var client = this;
        var content = '';
        var payload = JSON.stringify({
            "id": siteId,
            "LockSerial": lockId,
            "DisarmCode": code
        });

        var options = {
            host: this._apiEndpoint,
            port: 443,
            method: 'POST',
            headers: {
                'Accept': 'application/json, text/plain, */*',
                'Accept-Encoding': 'gzip, deflate, br, zstd',
                'Accept-Language': 'en-US,en;q=0.5',
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                'Authorization': this._accessToken,
                'Platform': 'mypage_web',
                'Version': '2.41.0',
                'Origin': `https://${this._sectoralarmsite}`,
                'Referer': `https://${this._sectoralarmsite}/`,
                'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0',
                'Connection': 'keep-alive'
            }
        };

        return new Promise(function(resolve, reject) {
            
            if (!client._accessToken) {
                reject(new SectorAlarmError('ERR_INVALID_SESSION', 'No access token available. Please authenticate first.'));
                return;
            }

            if (command == 'Lock') {
                options.path = '/Locks/Lock';
            } else if (command == 'Unlock') {
                options.path = '/Locks/Unlock';
            } else {
                reject(new SectorAlarmError('ERR_INVALID_COMMAND','Invalid command sent to act on lock for site. Should be Lock or Unlock'));
                return;
            }

            const requestWithRetry = (siteId, lockId, code, command, retry) => {

                var request = https.request(options, async function(response) {

                    if (response.statusCode == 401) {
                        if (retry != 0) {
                            await client.snooze(client._settings.retryDelayInMs);
                            retry--;
                            requestWithRetry(siteId, lockId, code, command, retry);
                            return;
                        } else {
                            reject(new SectorAlarmError('ERR_INVALID_SESSION', 'Access token expired or invalid, please re-authenticate'));
                        }
                    }

                    response.setEncoding("utf8");
                    response.on("data", function (chunk) {
                        content += chunk;
                    });
                    
                    response.on("end", function () {

                        if (content.indexOf("<!DOCTYPE html>")>0) {
                            reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. This error is often due to problems on sector alarm servers. No additional information'));
                        }

                        resolve(content);
                    });
                });

                request.on("error", function (e) {
                    reject(new SectorAlarmError('ERR_COMMUNICATION_ERROR', 'Communication with Sector Alarm failed. See innerError for details', e));
                });

                request.write(payload);
                request.end();
            }

            return requestWithRetry(siteId, lockId, code, command, retry);
        });
    }
};

module.exports = Client;
