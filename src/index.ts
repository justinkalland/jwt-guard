import Token from './lib/token'

declare module 'express-serve-static-core' {
  interface Request {
    token?: Token
  }
}

export default function (secretOrPublicKey: string) {
  return function (req, res, next) {
    if (req.method === 'OPTIONS') {
      return next()
    }

    let encodedJwt: string
    if (req.headers?.authorization !== undefined) {
      const parts = req.headers.authorization.split(' ')

      if (parts.length === 2 && parts[0] === 'Bearer') {
        encodedJwt = parts[1]
      }
    }

    req.token = new Token(encodedJwt, secretOrPublicKey)

    next()
  }
}
