import express from "express";

const app = express();
const port = 8080;

app.get("/", (req, res) => res.json({ success: true }));

app.listen(port, () => console.log("Listening on port 8080"));
