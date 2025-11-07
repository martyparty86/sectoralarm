'use strict'

const Client = require('./client.js');
const Parser = require('./parser.js');
const Settings = require("./settings.js");

module.exports = class Site {
    constructor(email, password, siteId, settings) {
        this._siteId = siteId;
        this._email = email;
        this._password = password;
        this._status = 'unknown';
        this._annex_status = 'unknown';

        if (settings != undefined) {
            this._settings = settings;
        } else {
            this._settings = new Settings();
        }

        this._client = new Client(this._settings);
        this._parser = new Parser();
    }

    login() {
        return Promise.resolve()
            .then(() => this._client.authenticate(this._email, this._password))
            .then(tokenData => {
                this._tokenData = tokenData;
                return tokenData;
            });
    }

    info() {
        return Promise.resolve()
            .then(() => this._client.getInfo(this._siteId))
                .then(info => this._parser.transformInfoToOutput(info))
                .then(info => this.formatOutput(info));
    }

    status() {
        return Promise.resolve()
            .then(() => this._client.getStatus(this._siteId))
            .then(status => this._parser.transformStatusToOutput(status))
            .then(status => this.formatOutput(status));
    }

    history(top = 10) {
        return Promise.resolve()
            .then(() => this._client.getHistory(this._siteId))
            .then(history => this._parser.transformHistoryToOutput(history, top))
            .then(history => this.formatOutput(history));
    }

    temperatures(sensorId) {
        return Promise.resolve()
            .then(() => this._client.getTemperatures(this._siteId))
            .then(temperatures => this._parser.transformTemperaturesToOutput(temperatures, sensorId))
            .then(temperatures => this.formatOutput(temperatures));
    }
 
    locks(lockId) {
        return Promise.resolve()
            .then(() => this._client.getLocks(this._siteId))
            .then(locks => this._parser.transformLocksToOutput(locks, lockId))
            .then(locks => this.formatOutput(locks));
    }

    cameras(cameraId) {
        return Promise.resolve()
            .then(() => this.formatOutput([]));
    }

    smartPlugs(smartPlugId) {
        return Promise.resolve()
            .then(() => this.formatOutput([]));
    }

    notify(checkIntervalInMs, changedCallback, changedAnnexCallback) {
        setInterval(async function() {
            var status = await this.status();
            var jsonStatus = JSON.parse(status);
            
            if (this._status == 'unknown')
            {
                this._status = jsonStatus.armedStatus;
                if (this._annex_status == 'unknown') 
                {
                    this._annex_status = jsonStatus.annexArmedStatus;
                }
                return;
            }

            if (this._status != jsonStatus.armedStatus)
            {
                this._status = jsonStatus.armedStatus;
                var formated = this.formatOutput(status);
                changedCallback(formated);
            }

            if (this._annex_status != jsonStatus.annexArmedStatus) 
            {
                this._annex_status = jsonStatus.annexArmedStatus;
                var formated = this.formatOutput(status);
                changedAnnexCallback(formated);
            }  

        }.bind(this), checkIntervalInMs);
    }   

    arm(code) {
        return Promise.resolve()
            .then(() => this._client.act(this._siteId, code, 'Total'))
            .then(action => this._parser.transformActionToOutput(action))
            .then(action => this.formatOutput(action));
    }

    partialArm(code) {
        return Promise.resolve()
            .then(() => this._client.act(this._siteId, code, 'Partial'))
            .then(action => this._parser.transformActionToOutput(action))
            .then(action => this.formatOutput(action));

    }

    annexArm(code) {
        return Promise.resolve()
            .then(() => this._client.act(this._siteId, code, 'ArmAnnex'))
            .then(action => this._parser.transformActionToOutput(action))
            .then(action => this.formatOutput(action));

    }

    disarm(code) {
        return Promise.resolve()
            .then(() => this._client.act(this._siteId, code, 'Disarm'))
            .then(action => this._parser.transformActionToOutput(action))
            .then(action => this.formatOutput(action));
    }

    annexDisarm(code) {
        return Promise.resolve()
            .then(() => this._client.act(this._siteId, code, 'DisarmAnnex'))
            .then(action => this._parser.transformActionToOutput(action))
            .then(action => this.formatOutput(action));
    }

    lock(lockId, code) {
        return Promise.resolve()
            .then(() => this._client.actOnLock(this._siteId, lockId, code, 'Lock'))
            .then(action => this._parser.transformActionOnLockToOutput(action))
            .then(action => this.formatOutput(action));

    }

    unlock(lockId, code) {
        return Promise.resolve()
            .then(() => this._client.actOnLock(this._siteId, lockId, code, 'Unlock'))
            .then(action => this._parser.transformActionOnLockToOutput(action))
            .then(action => this.formatOutput(action));
    }

    formatOutput(output) {
        return Promise.resolve()
            .then(() => {
                if (this._settings.jsonOutput == true) {
                    return JSON.stringify(output);
                }

                return output;
            })
        }
};