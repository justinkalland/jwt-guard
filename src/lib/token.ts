import Require from './require'
import jwt from 'jsonwebtoken'
import createError from 'http-errors'

export enum TokenStatus {
  Valid,
  Missing,
  Expired,
  Invalid,
  NotValidYet
}

interface DecodedJwtPayload {
  roles?: string[]
}

class Token {
  readonly roles: string[]
  readonly claims: object
  readonly status: TokenStatus

  constructor (encodedJwt?: string, secretOrPublicKey?: Buffer | string) {
    if (encodedJwt === undefined) {
      this.status = TokenStatus.Missing
      return
    }

    try {
      const payload: DecodedJwtPayload | string = jwt.verify(encodedJwt, secretOrPublicKey)
      if (typeof payload === 'string') {
        throw new Error('Does not support string payloads')
      }

      this.roles = payload.roles
      this.claims = payload

      this.status = TokenStatus.Valid
    } catch (err) {
      switch (err.name) {
        case 'TokenExpiredError':
          this.status = TokenStatus.Expired
          break
        case 'NotBeforeError':
          this.status = TokenStatus.NotValidYet
          break
        default:
          this.status = TokenStatus.Invalid
      }
    }
  }

  get require (): Require {
    return new Require(this)
  }

  get valid (): boolean {
    return this.status === TokenStatus.Valid
  }

  requireValid = (): void => {
    switch (this.status) {
      case TokenStatus.Valid:
        return
      case TokenStatus.Missing:
        throw new createError.Unauthorized('Token missing')
      case TokenStatus.Expired:
        throw new createError.Unauthorized('Token expired')
      case TokenStatus.NotValidYet:
        throw new createError.Unauthorized('Token not active yet')
      case TokenStatus.Invalid:
        throw new createError.Unauthorized('Token invalid')
    }
  }
}

export default Token
