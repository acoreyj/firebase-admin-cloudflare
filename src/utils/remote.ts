/* eslint-disable @typescript-eslint/explicit-function-return-type */
import * as jose from 'jose';
import { GetKeyFunction } from 'jose/dist/types/types';

import fetchJwks from './fetch_jwks';
import { JWKSNoMatchingKey, JOSENotSupported, JWKSInvalid, JWKSMultipleMatchingKeys } from './errors';

/**
 * Options for the remote JSON Web Key Set.
 */
export interface RemoteJWKSetOptions {
	/**
	 * Timeout (in milliseconds) for the HTTP request. When reached the request
	 * will be aborted and the verification will fail. Default is 5000 (5
	 * seconds).
	 */
	timeoutDuration?: number;

	/**
	 * Duration (in milliseconds) for which no more HTTP requests will be
	 * triggered after a previous successful fetch. Default is 30000 (30 seconds).
	 */
	cooldownDuration?: number;

	/**
	 * Maximum time (in milliseconds) between successful HTTP requests. Default is
	 * 600000 (10 minutes).
	 */
	cacheMaxAge?: number | typeof Infinity;

	/**
	 * An instance of
	 * [http.Agent](https://nodejs.org/api/http.html#http_class_http_agent) or
	 * [https.Agent](https://nodejs.org/api/https.html#https_class_https_agent) to
	 * pass to the
	 * [http.get](https://nodejs.org/api/http.html#http_http_get_options_callback)
	 * or
	 * [https.get](https://nodejs.org/api/https.html#https_https_get_options_callback)
	 * method's options. Use when behind an http(s) proxy. This is a Node.js
	 * runtime specific option, it is ignored when used outside of Node.js
	 * runtime.
	 */
	agent?: any;

	/**
	 * Optional headers to be sent with the HTTP request.
	 */
	headers?: Record<string, string>;
}

function isObjectLike(value: unknown): boolean {
  return typeof value === 'object' && value !== null
}

export default function isObject<T = object>(input: unknown): input is T {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== '[object Object]') {
    return false
  }
  if (Object.getPrototypeOf(input) === null) {
    return true
  }
  let proto = input
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto)
  }
  return Object.getPrototypeOf(input) === proto
}

function getKtyFromAlg(alg: unknown): string {
  switch (typeof alg === 'string' && alg.slice(0, 2)) {
  case 'RS':
  case 'PS':
    return 'RSA'
  case 'ES':
    return 'EC'
  case 'Ed':
    return 'OKP'
  default:
    throw new JOSENotSupported('Unsupported "alg" value for a JSON Web Key Set')
  }
}

interface Cache {
	[alg: string]: jose.KeyLike
}

/**
   * @private
   */
export function isJWKSLike(jwks: unknown): jwks is jose.JSONWebKeySet {
  return (
    jwks &&
		typeof jwks === 'object' &&
		// @ts-expect-error test
		Array.isArray(jwks.keys) &&
		// @ts-expect-error test
		jwks.keys.every(isJWKLike)
  )
}

function isJWKLike(key: unknown): boolean {
  return isObject<jose.JWK>(key)
}

function clone<T>(obj: T): T {
  if (typeof structuredClone === 'function') {
    return structuredClone(obj)
  }

  return JSON.parse(JSON.stringify(obj))
}

/**
   * @private
   */
export class LocalJWKSet {
  protected _jwks?: jose.JSONWebKeySet

  private _cached: WeakMap<jose.JWK, Cache> = new WeakMap()

  constructor(jwks: unknown) {
    if (!isJWKSLike(jwks)) {
      throw new JWKSInvalid('JSON Web Key Set malformed')
    }

    this._jwks = clone<jose.JSONWebKeySet>(jwks)
  }

  async getKey(protectedHeader: jose.JWSHeaderParameters, token: jose.FlattenedJWSInput): Promise<jose.KeyLike> {
    const { alg, kid } = { ...protectedHeader, ...token.header }
    const kty = getKtyFromAlg(alg)

    const candidates = this._jwks!.keys.filter((jwk) => {
      // filter keys based on the mapping of signature algorithms to Key Type
      let candidate = kty === jwk.kty

      // filter keys based on the JWK Key ID in the header
      if (candidate && typeof kid === 'string') {
        candidate = kid === jwk.kid
      }

      // filter keys based on the key's declared Algorithm
      if (candidate && typeof jwk.alg === 'string') {
        candidate = alg === jwk.alg
      }

      // filter keys based on the key's declared Public Key Use
      if (candidate && typeof jwk.use === 'string') {
        candidate = jwk.use === 'sig'
      }

      // filter keys based on the key's declared Key Operations
      if (candidate && Array.isArray(jwk.key_ops)) {
        candidate = jwk.key_ops.includes('verify')
      }

      // filter out non-applicable OKP Sub Types
      if (candidate && alg === 'EdDSA') {
        candidate = jwk.crv === 'Ed25519' || jwk.crv === 'Ed448'
      }

      // filter out non-applicable EC curves
      if (candidate) {
        switch (alg) {
        case 'ES256':
          candidate = jwk.crv === 'P-256'
          break
        case 'ES256K':
          candidate = jwk.crv === 'secp256k1'
          break
        case 'ES384':
          candidate = jwk.crv === 'P-384'
          break
        case 'ES512':
          candidate = jwk.crv === 'P-521'
          break
        }
      }

      return candidate
    })

    const { 0: jwk, length } = candidates

    if (length === 0) {
      throw new JWKSNoMatchingKey()
    } else if (length !== 1) {
      throw new JWKSMultipleMatchingKeys()
    }

    const cached = this._cached.get(jwk) || this._cached.set(jwk, {}).get(jwk)!
    if (cached[alg!] === undefined) {
      const keyObject = await jose.importJWK({ ...jwk, ext: true }, alg)

      if (keyObject instanceof Uint8Array || keyObject.type !== 'public') {
        throw new JWKSInvalid('JSON Web Key Set members must be public keys')
      }

      cached[alg!] = keyObject
    }

    return cached[alg!]
  }
}

/**
   * Returns a function that resolves to a key object from a locally
   * stored, or otherwise available, JSON Web Key Set.
   *
   * Only a single public key must match the selection process.
   *
   * @param jwks JSON Web Key Set formatted object.
   *
   * @example Usage
   * ```js
   * const JWKS = jose.createLocalJWKSet({
   *   keys: [
   *     {
   *       kty: 'RSA',
   *       e: 'AQAB',
   *       alg: 'PS256'
   *     },
   *     {
   *       crv: 'P-256',
   *       kty: 'EC',
   *       x: 'ySK38C1jBdLwDsNWKzzBHqKYEE5Cgv-qjWvorUXk9fw',
   *       y: '_LeQBw07cf5t57Iavn4j-BqJsAD1dpoz8gokd3sBsOo',
   *       alg: 'ES256'
   *     }
   *   ]
   * })
   *
   * const { payload, protectedHeader } = await jose.jwtVerify(jwt, JWKS, {
   *   issuer: 'urn:example:issuer',
   *   audience: 'urn:example:audience'
   * })
   * console.log(protectedHeader)
   * console.log(payload)
   * ```
   */
export function createLocalJWKSet(
  jwks: jose.JSONWebKeySet,
): GetKeyFunction<jose.JWSHeaderParameters, jose.FlattenedJWSInput> {
  return LocalJWKSet.prototype.getKey.bind(new LocalJWKSet(jwks))
}

export class RemoteJWKSet extends LocalJWKSet {
  private _url: globalThis.URL;

  private _timeoutDuration: number;

  private _cooldownDuration: number;

  private _cacheMaxAge: number;

  private _jwksTimestamp?: number;

  private _pendingFetch?: Promise<unknown>;

  private _options: Pick<RemoteJWKSetOptions, 'agent' | 'headers'>;

  constructor(url: unknown, options?: RemoteJWKSetOptions) {
    super({ keys: [] });

    this._jwks = undefined;

    if (!(url instanceof URL)) {
      throw new TypeError('url must be an instance of URL');
    }
    this._url = new URL(url.href);
    this._options = { agent: options?.agent, headers: options?.headers };
    this._timeoutDuration = typeof options?.timeoutDuration === 'number' ? options?.timeoutDuration : 5000;
    this._cooldownDuration =  typeof options?.cooldownDuration === 'number' ? options?.cooldownDuration : 30000;
    this._cacheMaxAge = typeof options?.cacheMaxAge === 'number' ? options?.cacheMaxAge : 600000;
  }

  coolingDown(): boolean {
    return typeof this._jwksTimestamp === 'number'
      ? Date.now() < this._jwksTimestamp + this._cooldownDuration
      : false;
  }

  fresh(): boolean {
    return typeof this._jwksTimestamp === 'number'
      ? Date.now() < this._jwksTimestamp + this._cacheMaxAge
      : false;
  }

  async getKeys(): Promise<jose.JWK[]> {
    if (!this._jwks || !this.fresh()) {
      await this.reload();
    }
    return this._jwks!.keys;
  }

  async getKey(
    protectedHeader: jose.JWSHeaderParameters,
    token: jose.FlattenedJWSInput
  ): Promise<jose.KeyLike> {
    if (!this._jwks || !this.fresh()) {
      await this.reload();
    }

    try {
      return await super.getKey(protectedHeader, token);
    } catch (err) {
      if (err instanceof JWKSNoMatchingKey) {
        if (this.coolingDown() === false) {
          await this.reload();
          return super.getKey(protectedHeader, token);
        }
      }
      throw err;
    }
  }

  async reload() {
    // see https://github.com/panva/jose/issues/355
    if (this._pendingFetch && isCloudflareWorkers()) {
      return new Promise<void>((resolve) => {
        const isDone = () => {
          if (this._pendingFetch === undefined) {
            resolve()
          } else {
            setTimeout(isDone, 5)
          }
        }
        isDone()
      })
    }

    if (!this._pendingFetch) {
      this._pendingFetch = fetchJwks(this._url, this._timeoutDuration, this._options)
        .then((json) => {
          if (!isJWKSLike(json)) {
            throw new JWKSInvalid('JSON Web Key Set malformed')
          }

          this._jwks = { keys: json.keys }
          this._jwksTimestamp = Date.now()
          this._pendingFetch = undefined
        })
        .catch((err: Error) => {
          this._pendingFetch = undefined
          throw err
        })
    }

    await this._pendingFetch
  }
}
function isCloudflareWorkers(): boolean {
  // @ts-expect-error WebSocketPair may not exist
  return typeof WebSocketPair === 'function'
}
interface URL {
	href: string;
}

/**
   * Returns a function that resolves to a key object downloaded from a
   * remote endpoint returning a JSON Web Key Set, that is, for example,
   * an OAuth 2.0 or OIDC jwks_uri. Only a single public key must match
   * the selection process.
   * The JSON Web Key Set is fetched when no key matches the selection
   * process but only as frequently as the `cooldownDuration` option allows,
   * to prevent abuse.
   *
   * @param url URL to fetch the JSON Web Key Set from.
   * @param options Options for the remote JSON Web Key Set.
   *
   * @example Usage
   * ```js
   * const JWKS = jose.createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs'))
   *
   * const { payload, protectedHeader } = await jose.jwtVerify(jwt, JWKS, {
   *   issuer: 'urn:example:issuer',
   *   audience: 'urn:example:audience'
   * })
   * console.log(protectedHeader)
   * console.log(payload)
   * ```
   */
export function createRemoteJWKSet(
  url: URL,
  options?: RemoteJWKSetOptions
): GetKeyFunction<jose.JWSHeaderParameters, jose.FlattenedJWSInput> {
  return RemoteJWKSet.prototype.getKey.bind(new RemoteJWKSet(url, options));
}