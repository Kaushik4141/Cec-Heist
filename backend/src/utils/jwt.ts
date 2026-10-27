export const DEFAULT_JWT_SECRET = 'cec-heist-super-secret-jwt-key-production-2026-cosc'

export function getJwtSecret(envSecret?: string): string {
  if (typeof envSecret === 'string' && envSecret.trim().length >= 32) {
    return envSecret.trim()
  }
  return DEFAULT_JWT_SECRET
}
