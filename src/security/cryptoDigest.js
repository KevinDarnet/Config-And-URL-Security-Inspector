/**
 * Utilidades criptográficas nativas basadas en Web Crypto API.
 * Permite comparar integridad de archivos .env entre entornos mediante su hash SHA-256
 * sin exponer secretos en claro, y generar secretos CSPRNG locales de 256 bits.
 */

export async function computeSha256Hex(rawContent) {
  if (typeof rawContent !== 'string' || rawContent.length === 0) {
    return null;
  }

  // crypto.subtle requiere Secure Context (HTTPS o localhost); evitamos excepción no controlada en HTTP LAN.
  if (!globalThis.crypto?.subtle) {
    console.warn('[CryptoDigest] Web Crypto Subtle API no disponible fuera de un contexto seguro (HTTPS/localhost).');
    return null;
  }

  try {
    const encodedPayload = new TextEncoder().encode(rawContent);
    const digestBuffer = await globalThis.crypto.subtle.digest('SHA-256', encodedPayload);
    return Array.from(new Uint8Array(digestBuffer), (byte) => byte.toString(16).padStart(2, '0')).join('');
  } catch (digestError) {
    console.error('[CryptoDigest] Error al calcular huella SHA-256 local:', digestError);
    return null;
  }
}

export function generateSecureSecretHex(byteLength = 32) {
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error('El generador CSPRNG del navegador (crypto.getRandomValues) no está disponible.');
  }

  const safeByteLength = Math.min(Math.max(Number(byteLength) || 32, 16), 64);
  const entropyBytes = new Uint8Array(safeByteLength);
  globalThis.crypto.getRandomValues(entropyBytes);

  return Array.from(entropyBytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
