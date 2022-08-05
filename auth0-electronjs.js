const {
    BrowserWindow,
    ipcMain,
    app
} = require('electron');
const OS = require("os");
const jwtDecode = require('jwt-decode');
const axios = require('axios');
const keytar = require("keytar");

let accessToken = null;
let profile = null;
let idToken = null;
let refreshToken = null;
let config = {};

async function refreshTokens() {
    const refreshToken = await keytar.getPassword(config.keytar.service, config.keytar.account);

    if (refreshToken) {
        const refreshOptions = {
            method: 'POST',
            url: `https://${config.auth0.domain}/oauth/token`,
            headers: {
                'content-type': 'application/json'
            },
            data: {
                grant_type: 'refresh_token',
                client_id: config.auth0.clientId,
                refresh_token: refreshToken
            }
        };

        try {
            const response = await axios(refreshOptions);
            accessToken = response.data.access_token;
            profile = jwtDecode(response.data.id_token);
            idToken = response.data.id_token;
        } catch (error) {
            await logout();
            throw error;
        }
    } else {
        throw new Error("No available refresh token.");
    }
}

async function loadTokens(callbackURL) {
    const urlParts = new URL(callbackURL);
    const query = urlParts.searchParams;

    const options = {
        method: 'POST',
        url: `https://${config.auth0.domain}/oauth/token`,
        headers: {'content-type': 'application/x-www-form-urlencoded'},
        data: new URLSearchParams({
            grant_type: 'authorization_code',
            client_id: config.auth0.clientId,
            code: query.get("code"),
            redirect_uri: config.auth0.redirectUri
        }),
    };

    try {
        const response = await axios(options);
        accessToken = response.data.access_token;
        profile = jwtDecode(response.data.id_token);
        idToken = response.data.id_token;
        refreshToken = response.data.refresh_token;
        if (refreshToken) {
            await keytar.setPassword(config.keytar.service, config.keytar.account, refreshToken);
        }
    } catch (error) {
        await logout();
        throw error;
    }
}

async function logout() {
    await keytar.deletePassword(config.keytar.service, config.keytar.account);
    accessToken = null;
    profile = null;
    refreshToken = null;
    idToken = null;
}

async function authorize(settings) {
    settings.auth0.scopes = settings.auth0.scopes || ["openid","profile","offline_access"]
    settings.keytar.account = settings.keytar.account || OS.userInfo().username;
    const auth0URL = `https://${settings.auth0.domain}/authorize?scope=${encodeURIComponent(settings.auth0.scopes.join(" "))}&response_type=code&client_id=${settings.auth0.clientId}&redirect_uri=${settings.auth0.redirectUri}${settings.auth0.audience ? `&audience=${settings.auth0.audience}` : ''}`;
    settings.auth0.authorizationUri = settings.auth0.authorizationUri || auth0URL;
    settings.authorizationWindow = settings.authorizationWindow || {
        width: 470,
        height: 680,
        webPreferences: {
            enableRemoteModule: false
        }
    };
    config = settings;
    try {
        await refreshTokens();
        settings.launchAppFn();
    } catch (err) {
        const authWindow = new BrowserWindow(settings.authorizationWindow);

        authWindow.loadURL(settings.auth0.authorizationUriIsFile ? `file://${__dirname}/${settings.auth0.authorizationUri}?auth_url=${encodeURIComponent(auth0URL)}` : settings.auth0.authorizationUri);

        if (settings.authorizationWindowFunction) {
            settings.authorizationWindowFunction(authWindow);
        }

        const webRequest = authWindow.webContents.session.webRequest;

        webRequest.onBeforeRequest({
            urls: [settings.auth0.redirectUri + '*']
        }, async ({
            url
        }) => {
            await loadTokens(url);
            settings.launchAppFn();
            authWindow.close();
        });

        authWindow.on('authenticated', () => {
            authWindow.close();
        });
    }
    ipcMain.handle(settings.calls.accessToken, () => accessToken);
    ipcMain.handle(settings.calls.profile, () => profile);
    ipcMain.on(settings.calls.logout, () => {
        BrowserWindow.getAllWindows().forEach(window => window.close());
        const logoutWindow = new BrowserWindow({
            show: false,
        });

        logoutWindow.loadURL(`https://${settings.auth0.domain}/v2/logout`);

        logoutWindow.on('ready-to-show', async () => {
            await logout();
            logoutWindow.close();
            app.relaunch();
            app.exit();
        });
    });
}

module.exports = {authorize};
