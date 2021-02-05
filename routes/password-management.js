const express = require("express");
const router = express.Router();
const connection = require("../config");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
var randomstring = require("randomstring");

// Passport modules for local strategy
const passport = require("passport");

// http://localhost:6000/password/change-password
router.post(
  "/change-password",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    const { current_password, new_password, user_id } = req.body;
    connection.query(
      "SELECT * FROM users where id = ?",
      [user_id],
      (err, results) => {
        if (err) res.status(500).send(err);
        if (!bcrypt.compareSync(current_password, results[0].password)) {
          res.status(500).send({
            message: "Incorrect password.",
          });
        }
        bcrypt.hash(new_password, 10, (err, hash) => {
          connection.query(
            "UPDATE users SET password = ? WHERE id = ?",
            [hash, user_id],
            (err, results) => {
              if (err) res.status(500).send(err);
              res
                .status(200)
                .send({ message: "password has been updated successfully" });
            }
          );
        });
      }
    );
  }
);

router.post("/reset-password", (req, res) => {
  const { email_recipient, subject, content } = req.body;
  connection.query(
    "SELECT * FROM users where email = ?",
    [email_recipient],
    (err, results) => {
      if (!results || !results.length)
        res.status(500).send({
          message: "The user with this email address does not exist",
        });
    }
  );
  const new_password = randomstring.generate(12);
  console.log(new_password);
  bcrypt.hash(new_password, 10, (err, hash) => {
    connection.query(
      "UPDATE users SET password = ? WHERE email = ?",
      [hash, email_recipient],
      (err, results) => {
        if (err) res.status(500).send(err);
        res.status(200).send({
          message: "check your email for your temporary password",
        });
      }
    );
  });

  sendEmail(email_recipient, subject, content, new_password);
});

const sendEmail = (email_recipient, subject, content, new_password) => {
  const smtpTransporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: "authexamplewcs@gmail.com",
      pass: "Auth1234!",
    },
  });

  const mailOptions = {
    from: "Auth App <authexamplewcs@gmail.com>",
    to: email_recipient,
    subject: subject,
    text: `${content} ${new_password}`,
  };

  smtpTransporter.sendMail(mailOptions, (error, response) => {
    if (error) {
      console.log(error);
    } else {
      console.log(`Notification email sent!`);
    }
    smtpTransporter.close();
  });
};

module.exports = router;
