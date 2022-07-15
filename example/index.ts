import express from "express";

import { Authenticator } from "../dist";

// Instantiating Authenticator
const authenticator = new Authenticator({
  accessKey: "verySecretAccessKeyPleaseChangeMeOrUseDotenv", // Never commit your secrets to public repo
  refreshKey: "verySecretRefreshKeyPleaseChangeMeOrUseDotenv", // Never commit your secrets to public repo
  // For DEMO purposes: expiration time is purposely set very low, so you can test the API
  // Default values are 5 minutes for access token and 24 hours for refresh token
  accessExpiresInSeconds: 10, // For DEMO purposes
  refreshExpiresInSeconds: 120, // For DEMO purposes
});

// Destructuring middlewares from Authenticator instance
const { createAccess, validateAccess, refreshAccess, revokeAccess } =
  authenticator;

// Creating express app
const app = express();
const port = 8080;

// Declaring our data
const database = {
  users: [
    {
      id: "iu821h8askjdqs12912",
      email: "john@doe.com",
      password: "123456",
    },
    {
      id: "0okjnhgt43erf1jians",
      email: "mary@jane.com",
      password: "123456",
    },
  ],
};

// Declaring our user lookup function
const findUser = (subject: string) => {
  return database.users.find((u) => u.id === subject);
};

// Sign In endpoint. "createAccess" middleware will generate access and refresh token
// only if you attach a "subject" property (with user ID) to res.locals object. Optionally you
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

// Refresh Endpoint. This endpoint will refresh your current access token, either
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

// Sign Out endpoint. "revokeAccess" middleware will destroy and invalidate tokens
// present in cookies. It also accepts a subject lookup function as an argument,
// that will find user related to tokens and attaches it to res.locals object for the next controller.
app.get("/signOut", revokeAccess(findUser), (req, res) => {
  res.json({
    message: "Access revoked for user " + res.locals.email,
  });
});

app.listen(port, () => console.log("Listening on port " + port));
