import { Hono } from 'hono'
import { sign } from 'hono/jwt'
import { compare } from 'bcryptjs'
import { eq, sql } from 'drizzle-orm'
import { createDb } from '../../db'
import { users } from '../../db/schema/users'
import { teams } from '../../db/schema/teams'
import type { CloudflareBindings } from '../../types'
import { getJwtSecret } from '../../utils/jwt'

const loginRoutes = new Hono<{ Bindings: CloudflareBindings }>()

loginRoutes.post('/', async (c) => {
  let body: {
    identifier?: unknown
    email?: unknown
    team_name?: unknown
    password?: unknown
  }

  try {
    body = await c.req.json()
  } catch {
    return c.json({ success: false, message: 'Invalid JSON body' }, 400)
  }

  const rawIdentifier =
    (typeof body.identifier === 'string' && body.identifier) ||
    (typeof body.email === 'string' && body.email) ||
    (typeof body.team_name === 'string' && body.team_name) ||
    ''

  const identifier = rawIdentifier.trim()
  const password = typeof body.password === 'string' ? body.password : ''

  if (!identifier || !password) {
    return c.json(
      { success: false, message: 'Team name/identifier and password are required' },
      400
    )
  }

  if (
    identifier.length > 254 ||
    new TextEncoder().encode(password).length > 72
  ) {
    return c.json(
      { success: false, message: 'Invalid identifier or password' },
      400
    )
  }

  const jwtSecret = getJwtSecret(c.env.JWT_SECRET)

  try {
    const db = createDb(c.env.cec_heist_db)
    const normalizedIdentifier = identifier.toLowerCase()

    // 1. Check if the identifier belongs to an Admin in `users`
    const adminUser = await db.query.users.findFirst({
      where: eq(sql`lower(${users.email})`, normalizedIdentifier),
    })

    if (adminUser) {
      const isMatch = await compare(password, adminUser.passwordHash)
      if (isMatch) {
        const now = Math.floor(Date.now() / 1000)

        const accessToken = await sign(
          {
            sub: String(adminUser.id),
            email: adminUser.email,
            role: adminUser.role,
            tokenType: 'access',
            iat: now,
            exp: now + 60 * 60,
          },
          jwtSecret,
          'HS256'
        )

        const refreshToken = await sign(
          {
            sub: String(adminUser.id),
            email: adminUser.email,
            role: adminUser.role,
            tokenType: 'refresh',
            iat: now,
            exp: now + 24 * 60 * 60,
          },
          jwtSecret,
          'HS256'
        )

        return c.json({
          success: true,
          message: 'Login successful',
          accessToken,
          refreshToken,
          expiresIn: 3600,
          refreshExpiresIn: 86400,
          user: {
            id: adminUser.id,
            email: adminUser.email,
            role: adminUser.role,
          },
        })
      }
    }

    // 2. Check if identifier belongs to a Team in `teams`
    const team = await db.query.teams.findFirst({
      where: eq(sql`lower(${teams.teamName})`, normalizedIdentifier),
    })

    if (team) {
      const isMatch = await compare(password, team.passwordHash)
      if (isMatch) {
        const now = Math.floor(Date.now() / 1000)
        const teamEmail = `${team.teamName.toLowerCase().replace(/[^a-z0-9_-]/g, '_')}@team.internal`

        const accessToken = await sign(
          {
            sub: String(team.id),
            teamId: team.id,
            teamName: team.teamName,
            email: teamEmail,
            role: 'user',
            tokenType: 'access',
            iat: now,
            exp: now + 60 * 60,
          },
          jwtSecret,
          'HS256'
        )

        const refreshToken = await sign(
          {
            sub: String(team.id),
            teamId: team.id,
            teamName: team.teamName,
            email: teamEmail,
            role: 'user',
            tokenType: 'refresh',
            iat: now,
            exp: now + 24 * 60 * 60,
          },
          jwtSecret,
          'HS256'
        )

        return c.json({
          success: true,
          message: 'Login successful',
          accessToken,
          refreshToken,
          expiresIn: 3600,
          refreshExpiresIn: 86400,
          user: {
            id: team.id,
            teamId: team.id,
            teamName: team.teamName,
            score: team.score,
            email: teamEmail,
            role: 'user',
          },
        })
      }
    }

    return c.json(
      { success: false, message: 'Invalid credentials' },
      401
    )
  } catch (error) {
    console.error('Login failed:', error)
    return c.json(
      { success: false, message: 'Unable to process login' },
      500
    )
  }
})

export default loginRoutes
