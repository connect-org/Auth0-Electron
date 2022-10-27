export declare class AuthError extends Error {
	constructor(message?: string);
}
export interface User {
    profile?: unknown;
    accessToken?: string;
    refreshToken?: string;
}
export interface ClientOptions {
    keytar: {
        service: string;
    };
    auth0: {
        clientId: string;
        domain: string;
        scopes?: Array<string>;
        audience?: string;
    };
    window: Electron.BrowserWindowConstructorOptions;
}
export declare class Client {
	private options;
	private authenticated;
	constructor(options: ClientOptions);
	private refreshTokens;
	private keytarLogout;
	private loadTokens;
	login(): Promise<User>;
	logout(): Promise<void>;
}
