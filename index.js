const express = require("express");
const app = express();
const connection = require("./config");
const authRouter = require("./routes/auth");
const passwordRouter = require("./routes/password-management");

const port = 6000;

connection.connect((err) => {
  if (err) throw err;
  console.log("Successfully connected to the database");
});

app.use(express.json());
app.use("/auth", authRouter);
app.use("/password", passwordRouter);

app.listen(port, (err) => {
  if (err) throw err;
  console.log(`App is listening at ${port}`);
});
