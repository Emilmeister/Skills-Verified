const cors = require("cors");
const express = require("express");
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.get("/status", (_request, response) => response.json({ status: "ok" }));
app.listen(3000, "127.0.0.1");
