import express from "express";

import { Authenticator } from "../dist";

const { refreshAccess, createAccess, validateAccess, revokeAccess } =
  new Authenticator({
    accessKey: "verySecretAccessKeyPleaseChangeMeOrUseDotenv",
    refreshKey: "VerySecretRefreshKeyPleaseChangeMeOrUseDotenv",
  });

const app = express();
const port = 8080;

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

const findUser = (id: string) => {
  return database.users.find((u) => u.id === id);
};

app.get("/signIn", createAccess(), (req, res) => {
  const { email, password } = req.query;

  const user = database.users.find((user) => user.email === email);

  if (!user) return res.sendStatus(401);
  if (user.password !== password) return res.sendStatus(401);

  res.subject = user.id;
  res.payload = { demo: "payload" };

  res.json({ success: true, user });
});

app.get("/refresh", refreshAccess(findUser), (req, res) => {
  res.json({ subject: req.subject });
});

app.get("/protected", validateAccess(true, findUser), (req, res) => {
  res.json({
    message: "This route is only accessible with valid access token",
    user: req.subject,
    payload: req.payload,
  });
});

app.get("/revoke", revokeAccess(findUser), (req, res) => {
  res.json({
    message: ("Access revoked for user " + req.subject.email) as any,
  });
});

app.listen(port, () => console.log("Listening on port 8080"));
