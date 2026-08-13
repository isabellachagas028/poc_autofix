/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import dns from 'node:dns/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

const PRIVATE_IPV4_RANGES: Array<[number, number]> = [
  [ipToInt('10.0.0.0'), ipToInt('10.255.255.255')],
  [ipToInt('127.0.0.0'), ipToInt('127.255.255.255')],
  [ipToInt('169.254.0.0'), ipToInt('169.254.255.255')],
  [ipToInt('172.16.0.0'), ipToInt('172.31.255.255')],
  [ipToInt('192.168.0.0'), ipToInt('192.168.255.255')],
  [ipToInt('0.0.0.0'), ipToInt('0.255.255.255')]
]

function ipToInt (ip: string): number {
  const parts = ip.split('.').map(Number)
  return ((parts[0] << 24) >>> 0) + ((parts[1] << 16) >>> 0) + ((parts[2] << 8) >>> 0) + (parts[3] >>> 0)
}

function isIpv4Address (host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) && host.split('.').every((p) => Number(p) >= 0 && Number(p) <= 255)
}

function isPrivateIpv4 (ip: string): boolean {
  const value = ipToInt(ip)
  return PRIVATE_IPV4_RANGES.some(([start, end]) => value >= start && value <= end)
}

function isLocalIpv6 (ip: string): boolean {
  const normalized = ip.toLowerCase()
  return normalized === '::1' || normalized.startsWith('fc') || normalized.startsWith('fd') || normalized.startsWith('fe80:')
}

async function isDisallowedHostname (hostname: string): Promise<boolean> {
  const normalizedHost = hostname.toLowerCase()
  if (normalizedHost === 'localhost' || normalizedHost.endsWith('.localhost')) {
    return true
  }

  if (isIpv4Address(normalizedHost)) {
    return isPrivateIpv4(normalizedHost)
  }

  try {
    const records = await dns.lookup(normalizedHost, { all: true })
    return records.some((record) => {
      if (record.family === 4) return isPrivateIpv4(record.address)
      return isLocalIpv6(record.address)
    })
  } catch {
    return true
  }
}

async function validateExternalImageUrl (value: string): Promise<string> {
  const parsed = new URL(value)

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP(S) URLs are allowed')
  }
  if (parsed.username || parsed.password) {
    throw new Error('URL credentials are not allowed')
  }
  if (await isDisallowedHostname(parsed.hostname)) {
    throw new Error('Target host is not allowed')
  }

  return parsed.toString()
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const validatedUrl = await validateExternalImageUrl(url)
          const response = await fetch(validatedUrl)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
