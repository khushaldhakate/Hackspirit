/**
 * Security Utilities for PhishGuard Redirect Analyzer (Phase 4)
 * Provides strict SSRF prevention, IP validation, and safe protocol validation.
 */

const dns = require('dns').promises;
const net = require('net');

/**
 * Check whether an IPv4 address is in a private, loopback, or reserved range
 * @param {string} ip - IPv4 string
 * @returns {boolean} True if private or reserved
 */
function isPrivateOrReservedIpv4(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed IPs treated as unsafe
  }

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (RFC1918 private)
  if (a === 10) return true;

  // 100.64.0.0/10 (Shared address space / Carrier-grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-local, AWS/GCP metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (RFC1918 private: 172.16.0.0 - 172.31.255.255)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF protocol assignments)
  if (a === 192 && b === 0 && c === 0) return true;

  // 192.0.2.0/24 (TEST-NET-1 documentation)
  if (a === 192 && b === 0 && c === 2) return true;

  // 192.168.0.0/16 (RFC1918 private)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;

  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast)
  if (a >= 224 && a <= 239) return true;

  // 240.0.0.0/4 (Reserved for future use)
  if (a >= 240) return true;

  // 255.255.255.255 (Broadcast)
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;

  return false;
}

/**
 * Check whether an IPv6 address is in a private, loopback, or reserved range
 * @param {string} ip - IPv6 string
 * @returns {boolean} True if private or reserved
 */
function isPrivateOrReservedIpv6(ip) {
  const cleanIp = ip.toLowerCase();

  // Loopback ::1
  if (cleanIp === '::1' || cleanIp === '0000:0000:0000:0000:0000:0000:0000:0001') {
    return true;
  }

  // Unspecified ::
  if (cleanIp === '::' || cleanIp === '0000:0000:0000:0000:0000:0000:0000:0000') {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:127.0.0.1 or ::ffff:7f00:1)
  if (cleanIp.startsWith('::ffff:')) {
    const ipv4Part = cleanIp.slice(7);
    if (net.isIPv4(ipv4Part)) {
      return isPrivateOrReservedIpv4(ipv4Part);
    }
    return true;
  }

  // Unique Local Address (ULA) fc00::/7 (fc00:: - fdff::)
  if (/^f[cd][0-9a-f]{2}:/i.test(cleanIp)) {
    return true;
  }

  // Link-Local fe80::/10 (fe80:: - febf::)
  if (/^fe[89ab][0-9a-f]:/i.test(cleanIp)) {
    return true;
  }

  // Multicast ff00::/8
  if (cleanIp.startsWith('ff')) {
    return true;
  }

  // Documentation 2001:db8::/32
  if (cleanIp.startsWith('2001:db8:') || cleanIp.startsWith('2001:0db8:')) {
    return true;
  }

  return false;
}

/**
 * Checks whether an IP address is private, loopback, link-local, or reserved
 * @param {string} ip
 * @returns {boolean}
 */
function isPrivateOrReservedIp(ip) {
  if (net.isIPv4(ip)) {
    return isPrivateOrReservedIpv4(ip);
  }
  if (net.isIPv6(ip)) {
    return isPrivateOrReservedIpv6(ip);
  }
  return true; // Unknown IP structure blocked by default
}

/**
 * Validate destination hostname and port against SSRF targets
 * @param {string} hostname - Domain or IP string
 * @param {number|string} port - Target port
 * @param {object} options - Optional test overrides (allowLocalMockPorts)
 * @returns {Promise<{ safe: boolean, reason?: string, resolvedIps?: string[] }>}
 */
async function validateDestinationSafe(hostname, port, options = {}) {
  if (!hostname || typeof hostname !== 'string') {
    return { safe: false, reason: 'Invalid or missing hostname' };
  }

  const cleanHost = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '');
  const numericPort = Number(port) || (options.protocol === 'https:' ? 443 : 80);

  // Test mode hook: allows specific local mock server port ONLY if explicitly passed in test options
  if (options.allowLocalMockPorts && Array.isArray(options.allowLocalMockPorts)) {
    if (options.allowLocalMockPorts.includes(numericPort)) {
      if (cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost === '::1') {
        return { safe: true, resolvedIps: ['127.0.0.1'] };
      }
    }
  }

  // 1. Static hostname checks
  if (
    cleanHost === 'localhost' ||
    cleanHost.endsWith('.localhost') ||
    cleanHost.endsWith('.local') ||
    cleanHost.endsWith('.internal') ||
    cleanHost.endsWith('.lan') ||
    cleanHost.endsWith('.corp') ||
    cleanHost === 'metadata.google.internal'
  ) {
    return { safe: false, reason: 'Private or loopback destination blocked (SSRF Protection)' };
  }

  // 2. Direct IP address check
  if (net.isIP(cleanHost)) {
    if (isPrivateOrReservedIp(cleanHost)) {
      return { safe: false, reason: 'Private or loopback destination blocked (SSRF Protection)' };
    }
    return { safe: true, resolvedIps: [cleanHost] };
  }

  // 3. DNS resolution check (prevent DNS rebinding / private resolution)
  try {
    const addresses = await dns.lookup(cleanHost, { all: true });
    if (!addresses || addresses.length === 0) {
      return { safe: false, reason: `DNS resolution failed for host: ${cleanHost}` };
    }

    const resolvedIps = addresses.map(a => a.address);

    for (const record of addresses) {
      if (isPrivateOrReservedIp(record.address)) {
        return {
          safe: false,
          reason: 'Host resolves to private or reserved IP address (SSRF Protection)',
          resolvedIps
        };
      }
    }

    return { safe: true, resolvedIps };
  } catch (err) {
    return { safe: false, reason: `DNS resolution failed: ${err.message}` };
  }
}

module.exports = {
  isPrivateOrReservedIpv4,
  isPrivateOrReservedIpv6,
  isPrivateOrReservedIp,
  validateDestinationSafe
};
