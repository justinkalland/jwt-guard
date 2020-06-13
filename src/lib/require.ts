import Token from './token'
import createError from 'http-errors'

enum Status {
  Fresh,
  Passing,
  Failed,
  Passed
}

class Require {
  private readonly _token: Token
  private _status: Status = Status.Fresh

  constructor (token: Token) {
    this._token = token
  }

  role = (name: string): Require => {
    const currentStatus = this._status

    if (currentStatus === Status.Passed || currentStatus === Status.Failed) {
      return this
    }

    const hasRole = this._token.roles?.includes(name)

    if (!hasRole) {
      this._status = Status.Failed
    } else {
      this._status = Status.Passing
    }

    return this
  }

  claim = (name: string, value: string | number | boolean): Require => {
    const currentStatus = this._status

    if (currentStatus === Status.Passed || currentStatus === Status.Failed) {
      return this
    }

    const compareValue = this._token.claims?.[name]

    if (compareValue === undefined || compareValue !== value) {
      this._status = Status.Failed
    } else {
      this._status = Status.Passing
    }

    return this
  }

  get and (): Require {
    return this
  }

  get or (): Require {
    const currentStatus = this._status

    if (currentStatus === Status.Passed) {
      return this
    }

    if (currentStatus === Status.Passing) {
      this._status = Status.Passed
      return this
    }

    this._status = Status.Fresh

    return this
  }

  get check (): boolean {
    if (!this._token.valid) {
      return false
    }

    const currentStatus = this._status

    if (currentStatus === Status.Passing || currentStatus === Status.Passed) {
      return true
    }

    return false
  }

  guard = (message?: string): void => {
    this._token.requireValid()

    if (!this.check) {
      throw new createError.Forbidden(message)
    }
  }
}

export default Require
