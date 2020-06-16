import express from 'express'
import request from 'supertest'
import jwtGuard from '../'
import * as support from './support'
import Token from '../lib/token'

describe('Express middleware', () => {
  it('works with no token', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.get('/ping', function (req, res) {
      expect(req.token).toBeInstanceOf(Token)

      res.send('pong')
    })

    const response = await request(app).get('/ping')
      .expect(200)

    expect(response.text).toEqual('pong')
  })

  it('works with different Auth header', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.get('/ping', function (req, res) {
      expect(req.token).toBeInstanceOf(Token)

      res.send('pong')
    })

    const response = await request(app).get('/ping')
      .set('Authorization', 'Ocookie ifoegnjrsfinoas')
      .expect(200)

    expect(response.text).toEqual('pong')
  })

  it('skips OPTIONS', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.options('/ping', function (req, res) {
      expect(req.token).toBeUndefined()

      res.sendStatus(200)
    })

    await request(app).options('/ping')
      .expect(200)
  })

  it('passes role', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.get('/ping', function (req, res) {
      req.token.require.role('admin').guard()

      res.status(200).send('pong')
    })

    const token = support.createJwt({
      roles: [
        'admin'
      ]
    })

    const response = await request(app).get('/ping')
      .set('Authorization', 'Bearer ' + token)
      .expect(200)

    expect(response.text).toEqual('pong')
  })

  it('fails role', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.get('/ping', function (req, res) {
      req.token.require.role('blog:read').guard()

      res.status(200).send('pong')
    })

    const token = support.createJwt({
      roles: [
        'admin'
      ]
    })

    const response = await request(app).get('/ping')
      .set('Authorization', 'Bearer ' + token)
      .expect(403)

    expect(response.text).not.toEqual('pong')
  })

  it('fails no token with role', async () => {
    const app = express()

    app.use(jwtGuard('secret'))

    app.get('/ping', function (req, res) {
      req.token.require.role('admin').guard()

      res.status(200).send('pong')
    })

    const response = await request(app).get('/ping')
      .expect(401)

    expect(response.text).not.toEqual('pong')
  })
})
