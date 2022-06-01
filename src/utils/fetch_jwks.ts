import * as jose from 'jose';


import fetch from 'node-fetch';
import { JOSEError, JWKSTimeout } from './errors';

const fetchJwks: FetchFunction = async (
  url: URL,
  timeout: number,
) => {
  let controller!: AbortController;
  let id!: ReturnType<typeof setTimeout>;
  let timedOut = false;
  if (typeof AbortController === 'function') {
    controller = new AbortController();
    id = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeout);
  }

  const response = await fetch(url.href, {
    signal: controller ? controller.signal : undefined,
    redirect: 'manual',
  }).catch((err) => {
    if (timedOut) throw new JWKSTimeout();
    throw err;
  });

  if (id !== undefined) clearTimeout(id);

  if (response.status !== 200) {
    throw new JOSEError(
      'Expected 200 OK from the JSON Web Key Set HTTP response',
    );
  }

  try {
    return await (response.json() as Promise<{ [propName: string]: unknown }>);
  } catch {
    throw new JOSEError(
      'Failed to parse the JSON Web Key Set HTTP response as JSON',
    );
  }
};
export default fetchJwks;

type AsyncOrSync<T> = Promise<T> | T;

export interface TimingSafeEqual {
  (a: Uint8Array, b: Uint8Array): boolean;
}
export interface SignFunction {
  (alg: string, key: unknown, data: Uint8Array): Promise<Uint8Array>;
}
export interface VerifyFunction {
  (
    alg: string,
    key: unknown,
    signature: Uint8Array,
    data: Uint8Array,
  ): Promise<boolean>;
}
export interface AesKwWrapFunction {
  (alg: string, key: unknown, cek: Uint8Array): AsyncOrSync<Uint8Array>;
}
export interface AesKwUnwrapFunction {
  (
    alg: string,
    key: unknown,
    encryptedKey: Uint8Array,
  ): AsyncOrSync<Uint8Array>;
}
export interface RsaEsEncryptFunction {
  (alg: string, key: unknown, cek: Uint8Array): AsyncOrSync<Uint8Array>;
}
export interface RsaEsDecryptFunction {
  (
    alg: string,
    key: unknown,
    encryptedKey: Uint8Array,
  ): AsyncOrSync<Uint8Array>;
}
export interface Pbes2KWEncryptFunction {
  (
    alg: string,
    key: unknown,
    cek: Uint8Array,
    p2c?: number,
    p2s?: Uint8Array,
  ): Promise<{
    encryptedKey: Uint8Array;
    p2c: number;
    p2s: string;
  }>;
}
export interface Pbes2KWDecryptFunction {
  (
    alg: string,
    key: unknown,
    encryptedKey: Uint8Array,
    p2c: number,
    p2s: Uint8Array,
  ): Promise<Uint8Array>;
}
export interface EncryptFunction {
  (
    enc: string,
    plaintext: Uint8Array,
    cek: unknown,
    iv: Uint8Array,
    aad: Uint8Array,
  ): AsyncOrSync<{
    ciphertext: Uint8Array;
    tag: Uint8Array;
  }>;
}
export interface DecryptFunction {
  (
    enc: string,
    cek: unknown,
    ciphertext: Uint8Array,
    iv: Uint8Array,
    tag: Uint8Array,
    additionalData: Uint8Array,
  ): AsyncOrSync<Uint8Array>;
}
export interface FetchFunction {
  (
    url: URL,
    timeout: number,
    options?: any,
  ): Promise<{ [propName: string]: unknown }>;
}
export interface DigestFunction {
  (
    digest: 'sha256' | 'sha384' | 'sha512',
    data: Uint8Array,
  ): AsyncOrSync<Uint8Array>;
}
export interface JWKImportFunction {
  (jwk: jose.JWK): AsyncOrSync<jose.KeyLike>;
}
export interface PEMImportFunction {
  (
    pem: string,
    alg: string,
    options?: jose.PEMImportOptions,
  ): AsyncOrSync<jose.KeyLike>;
}
interface ExportFunction<T> {
  (key: unknown): AsyncOrSync<T>;
}
export type JWKExportFunction = ExportFunction<jose.JWK>;
export type PEMExportFunction = ExportFunction<string>;
