import { BrowserWindow, ipcMain, app } from "electron";
import * as OS from "os";
import * as keytar from "keytar";
import jwtDecode from "jwt-decode";
import axios from "axios";

interface AuthorizationConfiguration {
	keytar: {
		service: string
	},
	auth0: {
		clientId: string,
		domain: string,
		scopes?: Array<string>,
		audience?: string
	},
	authorizationWindow?: Electron.BrowserWindowConstructorOptions,
	preload?(authWindow: BrowserWindow): void,
	onAuthorized(user?: AuthorizedUser): void,
	calls: {
		getUser: string,
		logout: string
	}
}

interface AuthorizedUser {
	profile?: object,
	accessToken?: string,
	refreshToken?: string
}

const user: AuthorizedUser = {};
let config: AuthorizationConfiguration;

async function refreshTokens() {
	const refreshToken = await keytar.getPassword(config.keytar.service, OS.userInfo().username);

	if (refreshToken) {
		const refreshOptions = {
			method: "POST",
			url: `https://${config.auth0.domain}/oauth/token`,
			headers: {
				"content-type": "application/json"
			},
			data: {
				grant_type: "refresh_token",
				client_id: config.auth0.clientId,
				refresh_token: refreshToken
			}
		};

		try {
			const response = await axios(refreshOptions);
			user.accessToken = response.data.access_token;
			user.profile = jwtDecode(response.data.id_token);
		} catch (error) {
			await logout();
			throw error;
		}
	} else {
		throw new Error("No available refresh token.");
	}
}

async function loadTokens(callbackURL: URL) {
	const query = callbackURL.searchParams;

	const options = {
		method: "POST",
		url: `https://${config.auth0.domain}/oauth/token`,
		headers: {"content-type": "application/x-www-form-urlencoded"},
		data: new URLSearchParams({
			grant_type: "authorization_code",
			client_id: config.auth0.clientId,
			code: query.get("code")!,
			redirect_uri: "https://localhost/callback",
		}),
	};

	try {
		const response = await axios(options);
		user.accessToken = response.data.access_token;
		user.profile = jwtDecode(response.data.id_token);
		user.refreshToken = response.data.refresh_token;
		if (user.refreshToken) {
			await keytar.setPassword(config.keytar.service, OS.userInfo().username, user.refreshToken);
		}
	} catch (error) {
		await logout();
		throw error;
	}
}

async function logout() {
	await keytar.deletePassword(config.keytar.service, OS.userInfo().username);
}

async function authorize(options: AuthorizationConfiguration) {
	config = options;
	config.auth0.scopes ??= ["openid", "profile", "offline_access"];
	config.authorizationWindow ??= {
		width: 470,
		height: 680
	};
	const authURL = new URL(`https://${config.auth0.domain}/authorize`);
	const authURLParams = new URLSearchParams({
		scope: config.auth0.scopes.join(" "),
		response_type: "code",
		client_id: config.auth0.clientId,
		redirect_uri: "https://localhost/callback",
	});

	if (config.auth0.audience) {
		authURLParams.set("audience", config.auth0.audience);
	}

	Array.from(authURLParams.entries()).forEach(entry => {
		authURL.searchParams.set(entry[0], entry[1]);
	});

	try {
		await refreshTokens();
		config.onAuthorized(user);
	} catch (err) {
		const authWindow = new BrowserWindow(config.authorizationWindow);
		authWindow.loadURL(authURL.toString());
		
		config.preload && config.preload(authWindow);

		const webRequest = authWindow.webContents.session.webRequest;

		webRequest.onBeforeRequest({ urls: ["https://localhost/callback*"] }, async ({ url }) => {
			await loadTokens(new URL(url));
			config.onAuthorized();

			authWindow.close();
		});

		// authWindow.on("authenticated", () => {
			// authWindow.close();
		// });
	}
	ipcMain.handle(config.calls.getUser, () => user);
	ipcMain.on(config.calls.logout, () => {
		BrowserWindow.getAllWindows().forEach(window => window.close());
		const logoutWindow = new BrowserWindow({ show: false });

		logoutWindow.loadURL(`https://${config.auth0.domain}/v2/logout`);

		logoutWindow.on("ready-to-show", async () => {
			await logout();
			logoutWindow.close();
			app.relaunch();
			app.exit();
		});
	});
}

export default authorize;
