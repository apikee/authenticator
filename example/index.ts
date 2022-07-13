import express from "express";

import { Authenticator } from "../dist";

const { createSignInTokens, refreshTokens } = new Authenticator({
  accessKey: "verysecretaccesskey",
  refreshKey: "verysecretrefreshkey",
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

app.get("/signIn", (req, res) => {
  const { email, password } = req.query;

  const user = database.users.find((user) => user.email === email);

  if (!user) return res.sendStatus(401);
  if (user.password !== password) return res.sendStatus(401);

  const { accessToken, refreshToken } = createSignInTokens(res, user.id);

  res.json({ success: true, user, accessToken, refreshToken });
});

app.get("/refresh", refreshTokens, (req, res) => {
  res.json("OK");
});

app.listen(port, () => console.log("Listening on port 8080"));
