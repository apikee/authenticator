## @apikee/authenticator

**Set of expressjs middlewares that creates, sends, validates and stores JWT access and refresh tokens. The goal is to make it easier for developers to implement secure authentication using JWT tokens.**

**This package was just released and is not properly tested on real life projects - I would recommend it for hobby projects.**

## Features

- Automatic generation of access and refresh tokens through `createAccess` middleware
- Tokens are automatically attached to response cookies as a HttpOnly Secure cookies
- Tokens are automatically validated through `validateAccess` middleware, including token reuse
- Access tokens are short-lived, can be refreshed through `refreshAccess` middleware
- Valid refresh tokens are stored in whitelist either in memory through MemoryStore, or in MongoDB, through MongoStore [@apikee/authenticator-mongostore](https://github.com/apikee/authenticator-mongostore)
- Developers can implement their own stores
- Whitelist is periodically cleared from expired tokens
- User lookup function can be provided to `validateAccess`, `refreshAccess` and `revokeAccess` middlewares. User will then be accessible in `res.locals.subject`
- Default access from multiple devices

**If you are using Nodejs Cluster Mode, you need to use a different store than default MemoryStore, since each worker in cluster mode would have it's own copy of token whitelist. Take a look at [@apikee/authenticator-mongostore](https://github.com/apikee/authenticator-mongostore)**

## Installation

```tsx
npm i @apikee/authenticator
```

## Demo

You can test `@apikee/authenticator` locally either by running code inside the `example` folder, or you take a look at the following demo API: https://github.com/apikee/authenticator-demo.git

## Usage

```tsx
import { Authenticator } from '@apikee/authenticator';

const { createAccess, validateAccess, refreshAccess, revokeAccess } = new Authenticator({
  accessKey: "verySecretAccessKeyPleaseChangeMeOrUseDotenv", // Never commit your secrets to public repo
  refreshKey: "verySecretRefreshKeyPleaseChangeMeOrUseDotenv", // Never commit your secrets to public repo
})
```

### Argument of Authenticator (object):

**accessKey: string;** - required - Secret key for access tokens

**refreshKey: string;** - required - Secret key for refresh tokens

**domain?: string;** - optional - Cookie domain

**accessExpiresInSeconds?: number;** - optional - Expiration time for access tokens in seconds (default is 5 minutes, applies to cookie MaxAge too)

**refreshExpiresInSeconds?: number;** - optional - Expiration time for refresh tokens in seconds (default is 24 hours, applies to cookie MaxAge too)

**sameSite?: "lax" | "none" | "strict";** - optional - Cookie Same-Site (default is "none")

**store?: Store;** - optional - Store for a whitelist of refresh tokens. Options are MemoryStore (default) or MongoStore

**cleanupEveryMs?: number;** - optional - How often will the whitelist be cleared of expired tokens (in milliseconds, default is 1 hour)

**rejectedAccessHandler?: (req: Request, res: Response, next: NextFunction) => void;** - optional - Custom reject access handler. This is used when tokens are invalid (default is res.sendStatus(401))

### new Authenticator(props) returns:

**createAccess(replace?: boolean)**

- Middleware
- Creates access and refresh tokens and attaches them to response cookies
- You need to attach `subject` property to `res.locals` for Authenticator to generate tokens - `res.locals.subject = USER_ID`
- Optionally you can also attach a `payload` property to `res.locals` with any additional data you want the access token to include - `res.locals.payload = { myData: "great data" }`
- By default, `createAccess` will allow users to be signed in from multiple devices. If you want to disable this behavior, pass `true` when calling `createAccess` - `createAccess(true)`

```tsx
// "createAccess" middleware will generate access and refresh token and make it part of response cookies.
// For that to happen, you need to attach a "subject" property (with user ID) to res.locals object. Optionally you
// can also attach a "payload" property to res.locals object. "payload" can be an object or
// string with additional data connected to subject. "payload" is then included in access
// token. By default, "createAccess()" allows users to sign in from multiple devices/places.
// If you want your users to sign in from one device/place only, pass true to createAccess
// -> createAccess(true)
app.get("/signIn", createAccess(), (req, res) => {
  const { email, password } = req.query;

  const user = database.users.find((user) => user.email === email);

  // Validating user credentials. If invalid, no tokens will be generated
  if (!user) return res.sendStatus(401);
  if (user.password !== password) return res.sendStatus(401);

  // Attaching "subject" and "payload" properties to res.locals object. This is a signal
  // for Authenticator to generate new tokens. If "subject" property is not present at
  // the time of sending response, no tokens will be generated.
  res.locals.subject = user.id;
  res.locals.payload = { demo: "payload" };

  // The authenticator intercepts the response, generates an access and
  // refresh token, adds it to the response cookie and sends it to the client
  res.json({ message: "User is signed in / access was granted", user });
});
```
  
**refreshAccess(subjectLookup?: (subject: string) => any | Promise\<any\>)** 

- Middleware
- Refreshes access token (either valid or invalid) from cookies
- Refresh token has to be valid
- New tokens are automatically attached to response cookies
- When calling this endpoint, make sure cookies are included with API call - `fetch(URL, { credentials: true })`
- Accepts `subjectLookup` function as an argument. This function finds and returns user by subject (User ID) provided when generating tokens through `createAccess` middleware. This user is then attached to `res.locals.subject` and accessible in next controller
- If `subjectLookup` function is not provided, the User ID will be passed to `res.locals.subject`
- The same applies to `payload` provided to access token

```tsx
// This endpoint will refresh your current access token, either
// valid or invalid. For that to happen, provided refresh token has to be valid.
// It's necessary to call this endpoint when "validateAccess" middleware fails
// with status 401 (Unauthorized). That means the access token is expired or otherwise
// invalid. If the "refreshAccess" return 401, that means the refresh token is invalid
// and therefore the access token cannot be refreshed. User then needs to sign in again.
// When calling this endpoint, make sure you include credentials (cookies) with the call.
// E.g. when using fetch API, include "credentials": true in the request options.
// "refreshAccess()" accepts one argument - subject lookup function. This is a
// function that should return a subject (e.g. user). "refreshAccess" passes to the function
// a subject (e.g. user ID) that is related with the token. You can then find and return
// the user by the ID in your subject lookup function. This subject (e.g. user) is then attached
// to res.locals.subject. Subject lookup function can be async.
app.get("/refresh", refreshAccess(findUser), (req, res) => {
  res.json({ message: "Tokens were refreshed", subject: res.locals.subject });
});

// Declaring our user lookup function
function findUser(subject: string) {
  return database.users.find((u) => u.id === subject);
};
```
  
**validateAccess(requireValidAccess: boolean = true, subjectLookup?: (subject: string) => any | Promise\<any\>)**

- Middleware
- Validates access token from cookies
- If valid, the next controller is invoked, `subject` and `payload` properties are attached to `res.locals` object - `res.locals.subject`, `res.locals.payload`
- When calling this endpoint, make sure cookies are included with API call - `fetch(URL, { credentials: true })`
- Accepts two arguments - `requireValidAccess (default true)` and `subjectLookup`
- If you pass `true` to `requireValidAccess`, only valid access token will be accepted
- If you pass `false` to `requireValidAccess`, even invalid tokens will be accepted, but no `subject` will be attached to `res.locals`. This is useful for endpoints that should be accessible for both authenticated and unauthenticated users
- `subjectLookup` is the same as `refreshAccess`

```tsx
// This can be any endpoint that requires authorization. "validateAccess" will check the
// tokens and if they are valid, the next() function will be invoked and your controller
// will be executed. If the tokens are invalid, "validateAccess" will stop any further
// execution and will response with status 401 (Unauthorized). Make sure to include credentials
// when calling this endpoint, the same as /refresh endpoint (check comment above).
// "validateAccess" accepts two arguments - requireValidAccess boolean and subjectLookup function.
// requireValidAccess (default true) makes sure the tokens are present and are valid.
// In some cases, you may have endpoints that are accessible for both authenticated and non-authenticated users.
// You can disable the strict token validation by passing false to "validateAccess" first argument,
// "validateAccess(false)". When false is provided and no/invalid access token is provided,
// "validateAccess" will invoke the next() function, but will not attach subject res.locals.
// You can then react to this situation as you wish in your controller.
// The subjectLookup is the same as refresh endpoint (comment above).
app.get("/protected", validateAccess(true, findUser), (req, res) => {
  res.json({
    message: "This route is only accessible with valid access token",
    user: res.locals.subject,
    payload: res.locals.payload,
  });
});

// Declaring our user lookup function
function findUser(subject: string) {
  return database.users.find((u) => u.id === subject);
};
```

**revokeAccess(subjectLookup?: (subject: string) => any | Promise\<any\>)**

- Middleware
- Removes tokens from cookies and from whitelist
- Accepts `subjectLookup` function as an argument - the same as `refreshAccess` or `validateAccess`

```tsx
// "revokeAccess" middleware will destroy and invalidate tokens
// present in cookies. It also accepts a subject lookup function as an argument,
// that will find user related to tokens and attaches it to res.locals object for the next controller.
app.get("/signOut", revokeAccess(findUser), (req, res) => {
  res.json({
    message: "Access revoked for user " + res.locals.email,
  });
});

// Declaring our user lookup function
function findUser(subject: string) {
  return database.users.find((u) => u.id === subject);
};
```

### Stores

**By default, Authenticator uses MemoryStore to store whitelist of refresh tokens. There is also MongoStore that can be used [@apikee/authenticator-mongostore](https://github.com/apikee/authenticator-mongostore). If you want to create Your own store, install the [@apikee/authenticator-common](https://github.com/apikee/authenticator-common) and extend the Store class. Take a look at source code of MongoStore or MemoryStore, or on example provided in README.md for [@apikee/authenticator-common](https://github.com/apikee/authenticator-common) to see, how your custom store should be implemented. It's quite easy.**

```tsx
import { JwtPayload } from "jsonwebtoken";

export class Store {
  addToken!: (
    token: string,
    subject: string,
    replace?: boolean
  ) => void | Promise<void>;
  findSubjectByToken!: (token: string) => string | Promise<string>;
  deleteToken!: (token: string) => void | Promise<void>;
  deleteAllTokensForSubject!: (subject: string) => void | Promise<void>;
  clearExpiredTokens!: (
    validateToken: (
      type: "access" | "refresh",
      token: string
    ) => JwtPayload | string | null
  ) => Promise<void>;
}
```
