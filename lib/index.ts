import { BrowserWindow, app } from "electron";
import * as OS from "os";
import * as keytar from "keytar";
import jwtDecode from "jwt-decode";
import fetch from "node-fetch";

/**
 * @error AuthError
 * @desc Error class for anything related to Auth
 */

export class AuthError extends Error {
	constructor(message?: string) {
		super(message);
		this.name = "AuthError";
	}
}

/**
 * @interface User
 * @desc Interface for user tokens and profile object
 */

export interface User {
	profile?: unknown,
	accessToken?: string,
	refreshToken?: string
}

const user: User = {};

export interface ClientOptions {
	keytar: {
		service: string
	},
	auth0: {
		clientId: string,
		domain: string,
		scopes?: Array<string>,
		audience?: string
	},
	window: Electron.BrowserWindowConstructorOptions
}

const DefaultClientOptions = {
	keytar: { },
	auth0: { scopes: ["openid", "profile", "offline_access"] }
};

export class Client {
	private options: ClientOptions;
	private authenticated: boolean;

	constructor(options: ClientOptions) {
		this.options = {...DefaultClientOptions, ...options};
		this.authenticated = false;
	}

	private async refreshTokens(): Promise<boolean> {
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

				// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const data: Record<any, any> = await response.json();

				user.accessToken = data.access_token;
				user.profile = jwtDecode(data.id_token);
				return true;
			} catch (error) {
				await this.keytarLogout();
				throw error;
			}
		} else {
			return false;
		}
	}
	
	private async keytarLogout() {
		await keytar.deletePassword(this.options.keytar.service, OS.userInfo().username);
	}

	private async loadTokens(callbackURL: URL) {
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
					// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
					code: query.get("code")!,
					redirect_uri: "https://localhost/callback",
				})
			});

			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			const data: Record<any, any> = await response.json();

			user.accessToken = data.access_token;
			user.profile = jwtDecode(data.id_token);
			user.refreshToken = data.refresh_token;
			if (user.refreshToken) {
				await keytar.setPassword(this.options.keytar.service, OS.userInfo().username, user.refreshToken);
			}
		} catch (error) {
			await this.keytarLogout();
			throw error;
		}
	}

	async login(): Promise<User> {
		if (this.refreshTokens()) {
			return user;
		} else {
			const authURL = new URL(`https://${this.options.auth0.domain}/authorize`);

			const authURLQuery: Record<string, string> = {
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

			// When the auth window redirects to the callback url
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
