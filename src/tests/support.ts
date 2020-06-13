import Token, { TokenStatus } from '../lib/token'
import jwt from 'jsonwebtoken'

export function createJwt (payload: object, status: TokenStatus = TokenStatus.Valid): string {
  switch (status) {
    case TokenStatus.Valid:
      return jwt.sign(payload, 'secret')
    case TokenStatus.Expired:
      return jwt.sign(payload,
        'secret', {
          expiresIn: '-1 hour'
        }
      )
    case TokenStatus.Invalid:
      return jwt.sign(payload, 'notsecret')
    case TokenStatus.NotValidYet:
      return jwt.sign(payload,
        'secret', {
          notBefore: '30 minutes'
        }
      )
  }
}

export function createToken (payload: object, status: TokenStatus = TokenStatus.Valid): Token {
  switch (status) {
    case TokenStatus.Missing:
      return new Token()
    default:
      return new Token(createJwt(payload, status), 'secret')
  }
}
