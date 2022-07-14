### @apikee/authenticator

**Authenticator is a set of middlewares for express.js that helps you with secure JWT authentication in your app. Simply create an instance of Authenticator and use returned functions as middlewares on your endpoints.**

## Features
- Stateless for developer
- Automatically generates access token with any payload you want
- Automatically generates refresh token
- Automatically sends both tokens as a part of cookies
- Takes care of token security, expiration, validates token reuse/misuse etc.
- Automatically validates access token and passes user and your custom payload to your API controller
- Automatic user lookup (specified by developer)
- Rejects invalid access tokens (can be disabled)
- Rejects invalid refresh tokens (cannot be disabled)
- Enables refreshing access token through refresh token
- Keeps whitelist of valid tokens (by default in memory through custom MemoryStore, but you can use different adapter, for example MongoStore or others)
- Default user access from multiple devices/places (can be disabled)
- Automatic Periodic cleanup of stale tokens

