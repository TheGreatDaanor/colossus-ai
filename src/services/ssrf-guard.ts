import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    result = (result << 8) | n;
  }
  return result >>> 0;
}

const DISALLOWED_IPV4_RANGES: [string, number][] = [
  ['127.0.0.0', 8], // loopback
  ['10.0.0.0', 8], // private
  ['172.16.0.0', 12], // private
  ['192.168.0.0', 16], // private
  ['169.254.0.0', 16], // link-local, includes the 169.254.169.254 cloud metadata address
];

function isDisallowedIPv4(ip: string): boolean {
  const int = ipv4ToInt(ip);
  if (int === null) return false;

  return DISALLOWED_IPV4_RANGES.some(([base, prefixLength]) => {
    const baseInt = ipv4ToInt(base);
    if (baseInt === null) return false;
    const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
    return (int & mask) === (baseInt & mask);
  });
}

function ipv6ToBigInt(ip: string): bigint | null {
  const doubleColonParts = ip.split('::');
  if (doubleColonParts.length > 2) return null;

  const head = doubleColonParts[0] ? doubleColonParts[0].split(':') : [];
  const tail = doubleColonParts.length === 2 && doubleColonParts[1] ? doubleColonParts[1].split(':') : [];

  let groups: string[];
  if (doubleColonParts.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const group of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(group)) return null;
    result = (result << 16n) | BigInt(parseInt(group, 16));
  }
  return result;
}

const DISALLOWED_IPV6_PREFIXES: [bigint, number][] = [
  [1n, 128], // ::1 loopback
  [ipv6ToBigInt('fe80::')!, 10], // link-local
  [ipv6ToBigInt('fc00::')!, 7], // unique-local (private)
];

function isDisallowedIPv6(ip: string): boolean {
  const mappedIPv4 = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ip);
  if (mappedIPv4?.[1] !== undefined) return isDisallowedIPv4(mappedIPv4[1]);

  const value = ipv6ToBigInt(ip);
  if (value === null) return false;

  return DISALLOWED_IPV6_PREFIXES.some(([base, prefixLength]) => {
    const shift = BigInt(128 - prefixLength);
    return value >> shift === base >> shift;
  });
}

export function isDisallowedAddress(ip: string): boolean {
  return ip.includes(':') ? isDisallowedIPv6(ip) : isDisallowedIPv4(ip);
}

export async function findDisallowedAddress(hostname: string): Promise<string | null> {
  if (isIP(hostname) !== 0) {
    return isDisallowedAddress(hostname) ? hostname : null;
  }

  try {
    const records = await lookup(hostname, { all: true });
    return records.find((record) => isDisallowedAddress(record.address))?.address ?? null;
  } catch {
    // A lookup failure isn't an SSRF signal — let the fetch attempt proceed and fail on its own terms.
    return null;
  }
}
