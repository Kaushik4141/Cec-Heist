import { verify } from 'hono/jwt'
import type { MiddlewareHandler } from 'hono'
import type { AppContext, AuthUser, CloudflareBindings } from '../types'
import { getJwtSecret } from '../utils/jwt'

export type AuthEnv = {
  Bindings: CloudflareBindings
  Variables: {
    user: AuthUser
  }
}

export const authMiddleware: MiddlewareHandler<AuthEnv> = async (c, next) => {
  const authorization = c.req.header('Authorization')

  if (!authorization?.startsWith('Bearer ')) {
    return c.json(
      { success: false, message: 'Authentication required' },
      401,
    )
  }

  const token = authorization.slice('Bearer '.length).trim()

  if (!token) {
    return c.json(
      { success: false, message: 'Invalid or expired token' },
      401,
    )
  }

  const jwtSecret = getJwtSecret(c.env.JWT_SECRET)
  let payload

  try {
    payload = await verify(token, jwtSecret, 'HS256')
  } catch {
    return c.json(
      { success: false, message: 'Invalid or expired token' },
      401,
    )
  }

  if (
    typeof payload.sub !== 'string' ||
    (payload.role !== 'user' && payload.role !== 'admin') ||
    payload.tokenType !== 'access'
  ) {
    return c.json(
      { success: false, message: 'Invalid token payload' },
      401,
    )
  }

  c.set('user', {
    id: payload.sub,
    email: typeof payload.email === 'string' ? payload.email : '',
    role: payload.role,
    teamId: typeof payload.teamId === 'number' ? payload.teamId : (payload.role === 'user' && !isNaN(Number(payload.sub)) ? Number(payload.sub) : undefined),
    teamName: typeof payload.teamName === 'string' ? payload.teamName : undefined,
  })

  await next()
}