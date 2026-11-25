import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// A collaborator token is a random nonce followed by a MAC over it, keyed with the
// shared secret. The listener records a hit only when the MAC checks out. Anyone can
// send the public zone traffic, but without the secret they cannot mint tokens it
// keeps, so they cannot flood real callbacks out of the bounded buffer.
//
// Base32 (RFC 4648, lower-case) so every symbol is valid in a DNS label; `byte & 31`
// picks a symbol without modulo bias. 12 nonce symbols carry 60 bits (unique across
// scans) and 8 MAC symbols 40 bits (out of reach of blind guessing): 20 in all.
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const NONCE_LENGTH = 12;
const MAC_LENGTH = 8;
export const TOKEN_PATTERN = new RegExp(`^[${ALPHABET}]{${NONCE_LENGTH + MAC_LENGTH}}$`);

const toBase32 = (bytes: Buffer, length: number) =>
  [...bytes.subarray(0, length)].map((byte) => ALPHABET[byte & 31]).join('');

function mac(secret: string, nonce: string): string {
  return toBase32(createHmac('sha256', secret).update(nonce).digest(), MAC_LENGTH);
}

export function mintSignedToken(secret: string): string {
  const nonce = toBase32(randomBytes(NONCE_LENGTH), NONCE_LENGTH);
  return nonce + mac(secret, nonce);
}

export function isSignedToken(secret: string, token: string): boolean {
  if (!TOKEN_PATTERN.test(token)) return false;
  const expected = Buffer.from(mac(secret, token.slice(0, NONCE_LENGTH)));
  return timingSafeEqual(expected, Buffer.from(token.slice(NONCE_LENGTH)));
}
