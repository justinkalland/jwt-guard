import { TokenStatus } from '../lib/token'
import * as support from './support'

describe('Require fail on non valid tokens', () => {
  it('invalid', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    }, TokenStatus.Invalid)

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()

    try {
      requireTry.guard()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('missing', () => {
    const token = support.createToken({}, TokenStatus.Missing)

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()

    try {
      requireTry.guard()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('expired', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ],
      name: 'bob'
    }, TokenStatus.Expired)

    const requireTry = token.require.claim('name', 'bob')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()

    try {
      requireTry.guard()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })

  it('not active yet', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ],
      name: 'bob'
    }, TokenStatus.NotValidYet)

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()

    try {
      requireTry.guard()
    } catch (err) {
      expect(err.status).toEqual(401)
    }
  })
})

describe('Has pass', () => {
  it('one role', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('two roles with and', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ]
    })

    const requireTry = token.require.role('admin').and.role('some:role')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('two roles without and', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ]
    })

    const requireTry = token.require.role('admin').role('some:role')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('one number claim', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45
    })

    const requireTry = token.require.claim('user_id', 45)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('one string claim', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require.claim('name', 'Bob Smith')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('one bool claim true', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      closed: true
    })

    const requireTry = token.require.claim('closed', true)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('one bool claim false', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      open: false
    })

    const requireTry = token.require.claim('open', false)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('two claims with and', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .claim('name', 'Bob Smith')
      .and.claim('user_id', 45)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('two claims without and', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .claim('name', 'Bob Smith')
      .claim('user_id', 45)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('role or role', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .role('admin')
      .or.role('some:role')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim or claim', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .claim('name', 'Bob Smith')
      .or.claim('user_id', 45)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim or role', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .claim('name', 'Bob Smith')
      .or.role('admin')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim or role and role', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'some:role'
      ],
      user_id: 45,
      name: 'Bob Smith'
    })

    const requireTry = token.require
      .claim('name', 'Bob Smith')
      .or.role('admin')
      .and.role('some:role')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })
})

describe('Has fail', () => {
  it('one role without roles', () => {
    const token = support.createToken({})

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('one role with roles', () => {
    const token = support.createToken({
      roles: [
        'email:read',
        'email:write'
      ]
    })

    const requireTry = token.require.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('two roles without roles', () => {
    const token = support.createToken({})

    const requireTry = token.require.role('admin')
      .and.role('blog:post')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('two roles with roles', () => {
    const token = support.createToken({
      roles: [
        'email:read',
        'email:write'
      ]
    })

    const requireTry = token.require.role('admin')
      .and.role('blog:post')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('one claim without claims', () => {
    const token = support.createToken({})

    const requireTry = token.require.claim('businessId', 123456)

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('one claim with claims', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('businessId', 123456)

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('two claims', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('businessId', 123456)
      .claim('some', 'value')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim or claim', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('some', 'value')
      .or.claim('businessId', 123456)

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim or role', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('some', 'value')
      .or.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim and role', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('some', 'value')
      .and.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim and role or role', () => {
    const token = support.createToken({
      businessId: 98765
    })

    const requireTry = token.require.claim('some', 'value')
      .and.role('owner')
      .or.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })
})

describe('Has fail with passes', () => {
  it('role(pass) and role(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.role('admin')
      .and.role('blog:post')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('role(fail) and role(pass)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.role('blog:post')
      .and.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim(fail) and role(pass)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.claim('email', 'bob@bob.com')
      .and.role('admin')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim(pass) and role(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ],
      id: 4
    })

    const requireTry = token.require.claim('id', 4)
      .and.role('car:drive')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('role(fail) and role(pass) or role(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.role('blog:post')
      .and.role('admin')
      .or.role('car:drive')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })

  it('claim(fail) or role(pass) and claim(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.claim('businessName', 'Smile')
      .or.role('admin')
      .and.claim('businessName', 'Sad')

    expect(requireTry.check).toEqual(false)
    expect(requireTry.guard).toThrowError()
  })
})

describe('Has or pass with fails', () => {
  it('role(pass) or role(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ]
    })

    const requireTry = token.require.role('admin')
      .or.role('blog:post')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim(pass) or claim(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ],
      customer_number: 44,
      good: true
    })

    const requireTry = token.require.claim('good', true)
      .or.claim('customer_number', 9)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim(pass) and role(pass) or claim(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin'
      ],
      customer_number: 44,
      good: true
    })

    const requireTry = token.require.claim('good', true)
      .and.role('admin')
      .or.claim('customer_number', 9)

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim(pass) and role(pass) and role(pass) or claim(fail) and role(pass)', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'blog:read',
        'blog:delete'
      ],
      customer_number: 44,
      good: true
    })

    const requireTry = token.require.claim('good', true)
      .and.role('admin')
      .and.role('blog:read')
      .or.claim('customer', 'bill')
      .and.role('blog:delete')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })

  it('claim(fail) or roll(pass) or claim(fail) or role(fail)', () => {
    const token = support.createToken({
      roles: [
        'admin',
        'blog:read',
        'blog:delete'
      ],
      customer_number: 44,
      good: true
    })

    const requireTry = token.require.claim('nopedont', true)
      .or.role('admin')
      .or.claim('customer', 'bill')
      .or.role('blog:write')

    expect(requireTry.check).toEqual(true)
    expect(requireTry.guard).not.toThrowError()
  })
})
