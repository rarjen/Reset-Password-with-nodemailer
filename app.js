require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const methodOverride = require("method-override");

const app = express();
const router = require("./routes");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(morgan("dev"));
app.set("view engine", "ejs");
app.use(methodOverride("_method"));
app.use(router);

app.use((req, res, next) => {
  return res.json({
    status: false,
    message: "are you lost?",
    data: null,
  });
});

app.use((err, req, res, next) => {
  console.log(err);
  return res.json({
    status: false,
    message: err.message,
    data: null,
  });
});

const { HTTP_PORT } = process.env;

app.listen(HTTP_PORT, () => {
  console.log(`LISTENING TO PORT ${HTTP_PORT}`);
});
