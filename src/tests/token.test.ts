import Token, { TokenStatus } from '../lib/token'
import * as support from './support'
import jwt from 'jsonwebtoken'

describe('Token', () => {
  it('valid with empty payload', () => {
    const token = support.createToken({})

    expect(token.status).toEqual(TokenStatus.Valid)
    expect(token.requireValid).not.toThrow()
  })

  it('valid with no roles', () => {
    const token = support.createToken({ user_id: 4 })

    expect(token.status).toEqual(TokenStatus.Valid)
    expect(token.requireValid).not.toThrow()
  })

  it('valid with one role', () => {
    const token = support.createToken({ roles: ['admin'] })

    expect(token.status).toEqual(TokenStatus.Valid)
    expect(token.requireValid).not.toThrow()
  })

  it('valid with multiple roles', () => {
    const token = support.createToken({ roles: ['admin', 'email:write'] })

    expect(token.status).toEqual(TokenStatus.Valid)
    expect(token.requireValid).not.toThrow()
  })

  it('invalid with string payload', () => {
    const encodedJwt = jwt.sign('I am a string', 'secret')

    const token = new Token(encodedJwt, 'secret')

    expect(token.status).toEqual(TokenStatus.Invalid)
    expect(token.requireValid).toThrow()

    try {
      token.requireValid()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('invalid', () => {
    const token = support.createToken({ anything: 'sure' }, TokenStatus.Invalid)

    expect(token.status).toEqual(TokenStatus.Invalid)
    expect(token.requireValid).toThrow()

    try {
      token.requireValid()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('expired', () => {
    const token = support.createToken({ anything: 'sure' }, TokenStatus.Expired)

    expect(token.status).toEqual(TokenStatus.Expired)
    expect(token.requireValid).toThrow()

    try {
      token.requireValid()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('not active yet', () => {
    const token = support.createToken({ anything: 'sure' }, TokenStatus.NotValidYet)

    expect(token.status).toEqual(TokenStatus.NotValidYet)
    expect(token.requireValid).toThrow()

    try {
      token.requireValid()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('missing', () => {
    const token = support.createToken({ anything: 'sure' }, TokenStatus.Missing)

    expect(token.status).toEqual(TokenStatus.Missing)
    expect(token.requireValid).toThrow()

    try {
      token.requireValid()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })
})
