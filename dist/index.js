import { BrowserWindow, app } from "electron";
import * as OS from "os";
import * as keytar from "keytar";
import jwtDecode from "jwt-decode";
import fetch from "node-fetch";
export class AuthError extends Error {
	constructor(message) {
		super(message);
		this.name = "AuthError";
	}
}
const user = {};
const DefaultClientOptions = {
	keytar: {},
	auth0: { scopes: ["openid", "profile", "offline_access"] }
};
export class Client {
	options;
	authenticated;
	constructor(options) {
		this.options = { ...DefaultClientOptions, ...options };
		this.authenticated = false;
	}
	async refreshTokens() {
		const refreshToken = await keytar.getPassword(this.options.keytar.service, OS.userInfo().username);
		if (refreshToken) {
			try {
				const response = await fetch(`https://${this.options.auth0.domain}/oauth/token`, {
					method: "POST",
					headers: {
						"Content-Type": "application/x-www-form-urlencoded"
					},
					body: new URLSearchParams({
						grant_type: "refresh_token",
						client_id: this.options.auth0.clientId,
						refresh_token: refreshToken
					})
				});
				const data = await response.json();
				user.accessToken = data.access_token;
				user.profile = jwtDecode(data.id_token);
				return true;
			}
			catch (error) {
				await this.keytarLogout();
				throw error;
			}
		}
		else {
			return false;
		}
	}
	async keytarLogout() {
		await keytar.deletePassword(this.options.keytar.service, OS.userInfo().username);
	}
	async loadTokens(callbackURL) {
		try {
			const query = callbackURL.searchParams;
			const response = await fetch(`https://${this.options.auth0.domain}/oauth/token`, {
				method: "POST",
				headers: {
					"Content-Type": "application/x-www-form-urlencoded"
				},
				body: new URLSearchParams({
					grant_type: "authorization_code",
					client_id: this.options.auth0.clientId,
					code: query.get("code"),
					redirect_uri: "https://localhost/callback",
				})
			});
			const data = await response.json();
			user.accessToken = data.access_token;
			user.profile = jwtDecode(data.id_token);
			user.refreshToken = data.refresh_token;
			if (user.refreshToken) {
				await keytar.setPassword(this.options.keytar.service, OS.userInfo().username, user.refreshToken);
			}
		}
		catch (error) {
			await this.keytarLogout();
			throw error;
		}
	}
	async login() {
		if (this.refreshTokens()) {
			return user;
		}
		else {
			const authURL = new URL(`https://${this.options.auth0.domain}/authorize`);
			const authURLQuery = {
				scope: this.options.auth0.scopes.join(" "),
				response_type: "code",
				client_id: this.options.auth0.clientId,
				redirect_uri: "https://localhost/callback"
			};
			if (this.options.auth0.audience) {
				authURLQuery.audience = this.options.auth0.audience;
			}
			Object.keys(authURLQuery).forEach(key => {
				authURL.searchParams.append(key, authURLQuery[key]);
			});
			const authWindow = new BrowserWindow(this.options.window);
			authWindow.loadURL(authURL.href);
			const webRequest = authWindow.webContents.session.webRequest;
			webRequest.onBeforeRequest({ urls: ["connect://auth/callback*"] }, async ({ url }) => {
				await this.loadTokens(new URL(url));
				authWindow.close();
				return user;
			});
		}
	}
	async logout() {
		if (!this.authenticated) {
			throw new AuthError("Logout: Attemped to logout while client is not authenticated");
		}
		BrowserWindow.getAllWindows().forEach(window => window.close());
		await fetch(`https://${this.options.auth0.domain}/v2/logout`);
		await this.keytarLogout();
		app.relaunch();
		app.exit();
	}
}
