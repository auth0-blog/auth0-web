import {Auth0UserProfile, AuthOptions, WebAuth} from 'auth0-js';

const IMPLICTY_RESPONSE_TYPE = 'token id_token';

export interface AuthResult { accessToken: string, idToken: string, expiresIn: number }

export interface Subscriber {
  (authenticated: boolean, audience?: string): void;
}

interface TokenMap {
  [key: string]: {
    accessToken: string,
    expiresAt: number,
  };
}

interface SubscriberMap {
  [key: string]: Subscriber;
}

const DEFAULT_KEY = 'default';

export default class Auth0Web {
  protected _auth0Client: WebAuth;
  private _accessTokens: TokenMap = {};
  private _currentProperties: AuthOptions;
  private _idToken: string;
  private _profile: Auth0UserProfile;
  private _subscribers: SubscriberMap = {};

  constructor(properties: AuthOptions) {
    this._currentProperties = properties;
    this._auth0Client = new WebAuth({
      ...properties,
      responseType: IMPLICTY_RESPONSE_TYPE
    });
  }

  getProfile(): Auth0UserProfile {
    return this._profile;
  }

  getAccessToken(audience ?: string): string {
    if (!this._accessTokens[audience || DEFAULT_KEY]) return;
    return this._accessTokens[audience || DEFAULT_KEY].accessToken;
  }

  getProperties() {
    return this._currentProperties;
  }

  signIn(): void {
    this._auth0Client.authorize();
  }

  signOut(returnTo?: string): void {
    this.clearSession();
    const {clientID} = this._currentProperties;
    this._auth0Client.logout({
      returnTo,
      clientID,
    });
  }

  isAuthenticated(audience?: string): boolean {
    if (this._accessTokens[audience || DEFAULT_KEY]) return true;
    return false;
  }

  parseHash(): Promise<Auth0UserProfile> {
    return new Promise((resolve, reject) => {
      this._auth0Client.parseHash(async (err, authResult: AuthResult) => {
        if (err) return reject(err);
        window.location.hash = '';
        try {
          resolve(await this.loadProfile(authResult));
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  checkSession(audience?: string, scope = 'openid'): Promise<boolean> {
    return new Promise<boolean>((resolve, reject) => {
      this._auth0Client.checkSession({audience, scope}, async (error, authResult) => {
        if (error && error.error !== 'login_required') {
          // some other error
          return reject(error);
        } else if (error) {
          // explicit authentication required
          return resolve(false);
        }

        if (this.isAuthenticated()) {
          const expiresAt = authResult.expiresIn * 1000 + Date.now();
          this.addAccessToken(authResult.accessToken, expiresAt, audience);
          return resolve(true);
        }

        try {
          await this.handleAuthResult(authResult, audience);
          resolve(true);
        } catch (err) {
          reject(err);
        }
      });
    });
  }

  // returns a function to unsubscribe
  subscribe(subscriber: Subscriber): () => void {
    const subscriberKey = Date.now();
    this._subscribers[subscriberKey] = subscriber;
    return () => {
      delete this._subscribers[subscriberKey];
    }
  }

  private addAccessToken(accessToken: string, expiresAt: number, audience?: string): void {
    if (!this._accessTokens) this._accessTokens = {};

    const accessTokenDetails = {
      accessToken,
      expiresAt,
    };

    if (!this._accessTokens[DEFAULT_KEY]) this._accessTokens[DEFAULT_KEY] = accessTokenDetails;

    if (audience) this._accessTokens[audience] = accessTokenDetails;
  }

  private clearSession() {
    delete this._profile;
    this._accessTokens = {};
    delete this._idToken;
    this.notifySubscribers(false);
  }

  private handleAuthResult(authResult: AuthResult, audience ?: string): Promise<Auth0UserProfile> {
    window.location.hash = '';
    return this.loadProfile(authResult, audience);
  }

  private loadProfile(authResult: AuthResult, audience?: string): Promise<Auth0UserProfile> {
    return new Promise((resolve, reject) => {
      this._auth0Client.client.userInfo(authResult.accessToken, (err, profile: Auth0UserProfile) => {
        if (err) return reject(err);

        const expiresAt = authResult.expiresIn * 1000 + Date.now();
        this.addAccessToken(authResult.accessToken, expiresAt, audience);
        this._idToken = authResult.idToken;
        this._profile = profile;

        this.notifySubscribers(true);
        resolve();
      });
    });
  }

  private notifySubscribers(authenticated: boolean, audience?: string) {
    Object.keys(this._subscribers).forEach((subscriberKey: string) => {
      this._subscribers[subscriberKey](authenticated, audience);
    });
  }
}
