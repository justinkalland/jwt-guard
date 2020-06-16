# jwt-guard

Provides Express middleware for guarding resources based on JWT roles and claims. Supports chaining with `and`/`or`.

Works great with Auth0 or other JWT implementations.

```typescript
app.get('/user/:id', function (req, res) {
    req.token.require
        .role('admin')
        .or.claim('user_id', req.params.id)
        .guard()    

    res.send('You are allowed to access this user!')
})
```

<!-- TOC is automatically generated -->
<!-- update with `npx markdown-toc -i README.md` -->
<!-- toc -->

- [Installation](#installation)
- [Usage](#usage)
  * [Guard](#guard)
    + [Using roles](#using-roles)
    + [Using claims](#using-claims)
    + [Chaining roles and claims](#chaining-roles-and-claims)
  * [Check](#check)
  * [Getting a claim](#getting-a-claim)

<!-- tocstop -->

## Installation

```bash
npm install jwt-guard
```

Include the Express middleware as early as possible. It validates and decodes the JWT from the `Authorization: Bearer` header using [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken).

```typescript
import express from 'express'
import jwtGuard from 'jwt-guard'

const app = express()

app.use(jwtGuard('secret_key_shhhhh'))
```

## Usage
`.token` is added to every request object. This can be used to guard access by requiring roles and/or claims.

### Guard

Guarding throws an [HTTP error](https://www.npmjs.com/package/http-errors) on failure.

#### Using roles

Roles come from the `roles:` claim in the JWT.

```typescript
app.get('/admin-area', function (req, res) {
    req.token.require.role('admin').guard()
    
    res.send('Welcome to the secret area')
})
```

#### Using claims

Claims come from the `payload` of the JWT. Often this is used to hold things like `user_id`.

```typescript
app.post('/user', function (req, res) {
    const userId = req.body.user_id

    req.token.require.claim('user_id', user_id)
        .guard('Sorry you can only update your own account.')

    // passed, update logic here
})
```

#### Chaining roles and claims

You can require multiple roles and claims by chaining with `or` and `and`.

```typescript
app.post('/blog', function (req, res) {
    req.token.require
        .role('blog:post')
        .or.role('blog:admin')
        .or.role('god')
        .guard()
    
    // passed, post the blog
})
```
```typescript
app.delete('/blog/:id', function (req, res) {
    const blogPost = '...'

    req.token.require
        .role('admin')
        .or.claim('user_id', blogPost.ownerUserId)
        .and.role('blog:delete')
        .guard()
    
    // passed, delete the blog
})
```

### Check

Works like `.guard()` but returns `true`/`false` instead of throwing an error. Supports [chaining](#Chaining roles and claims) as well.

```typescript
app.get('/admin-area', function (req, res) {
    const isAdmin = req.token.require.role('admin').check
    
    if(isAdmin) {
        res.send('Welcome to the secret area')
    } else{
        res.redirect('/')
    }
})
```

### Getting a claim

Retrieving the value of a claim is easy

```typescript
app.get('/', function (req, res) {
    const name = req.token.claims.name
    
    res.send(`Hello ${name}`)
})
```
