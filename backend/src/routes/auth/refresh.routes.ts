import { Hono } from 'hono'
import { sign, verify } from 'hono/jwt'
import { eq } from 'drizzle-orm'
import { createDb } from '../../db'
import { users } from '../../db/schema/users'
import { teams } from '../../db/schema/teams'
import type { CloudflareBindings } from '../../types'
import { getJwtSecret } from '../../utils/jwt'

const refreshRoutes = new Hono<{ Bindings: CloudflareBindings }>()

refreshRoutes.post('/', async (c) => {
  const body = await c.req.json<{ refreshToken?: unknown }>().catch(() => null)

  if (
    !body ||
    typeof body.refreshToken !== 'string' ||
    !body.refreshToken
  ) {
    return c.json(
      { success: false, message: 'Refresh token is required' },
      400
    )
  }

  const jwtSecret = getJwtSecret(c.env.JWT_SECRET)

  try {
    const payload = await verify(
      body.refreshToken,
      jwtSecret,
      'HS256'
    )

    if (
      typeof payload.sub !== 'string' ||
      payload.tokenType !== 'refresh'
    ) {
      return c.json(
        { success: false, message: 'Invalid refresh token' },
        401
      )
    }

    const db = createDb(c.env.cec_heist_db)
    const now = Math.floor(Date.now() / 1000)

    if (payload.role === 'admin') {
      const admin = await db.query.users.findFirst({
        where: eq(users.id, Number(payload.sub)),
      })

      if (!admin) {
        return c.json(
          { success: false, message: 'Admin not found' },
          401
        )
      }

      const accessToken = await sign(
        {
          sub: String(admin.id),
          email: admin.email,
          role: admin.role,
          tokenType: 'access',
          iat: now,
          exp: now + 60 * 60,
        },
        jwtSecret,
        'HS256'
      )

      return c.json({
        success: true,
        accessToken,
        expiresIn: 3600,
      })
    } else {
      const team = await db.query.teams.findFirst({
        where: eq(teams.id, Number(payload.sub)),
      })

      if (!team) {
        return c.json(
          { success: false, message: 'Team not found' },
          401
        )
      }

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

      return c.json({
        success: true,
        accessToken,
        expiresIn: 3600,
      })
    }
  } catch {
    return c.json(
      { success: false, message: 'Invalid or expired refresh token' },
      401
    )
  }
})

export default refreshRoutes
