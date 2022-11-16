const { User } = require("../models");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const util = require("../utils");

const { JWT_KEY } = process.env;

module.exports = {
  signUp: (req, res, next) => {
    return res.render("auth/register", { error: null });
  },
  signIn: (req, res, next) => {
    return res.render("auth/login", { error: null });
  },
  register: async (req, res, next) => {
    try {
      const { name, email, password, confirm_password } = req.body;
      if (password !== confirm_password)
        return res.render("auth/register", { error: "Password Doesn't Match" });

      const userExist = await User.findOne({ where: { email } });
      if (userExist)
        return res.render("auth/register", { error: "Email Already Used" });

      const hashed = await bcrypt.hash(password, 10);
      const newUser = await User.create({ name, email, password: hashed });

      return res.render("auth/login", { error: null });
    } catch (error) {
      next(error);
    }
  },
  login: async (req, res, next) => {
    try {
      const { email, password } = req.body;

      const userExist = await User.findOne({ where: { email } });
      if (!userExist)
        return res.render("auth/login", { error: "User Not Found!" });

      //check password
      const correct = await bcrypt.compare(password, userExist.password);

      if (!correct)
        return res.render("auth/login", { error: "Wrong Password!" });

      return res.render("index");
    } catch (error) {
      next(error);
    }
  },
  forgotPasswordView: (req, res) => {
    return res.render("auth/forgot-password", { message: null });
  },
  forgotPassword: async (req, res, next) => {
    try {
      const { email } = req.body;

      const user = await User.findOne({ where: { email } });
      if (user) {
        const payload = { user_id: user.id };
        const token = jwt.sign(payload, JWT_KEY);
        const link = `http://localhost:3000/auth/reset-password?token=${token}`;

        const htmlEmail = await util.email.getHtml("reset-password.ejs", {
          name: user.name,
          link: link,
        });

        await util.email.sendEmail(
          user.email,
          "Reset Your Password",
          htmlEmail
        );
      }

      return res.render("auth/forgot-password", {
        message:
          "We will send email for reset password if the email is exist on our database!",
      });
    } catch (error) {
      next(error);
    }
  },
  resetPasswordView: (req, res) => {
    const { token } = req.query;
    return res.render("auth/reset-password", { message: null, token });
  },
  resetPassword: async (req, res, next) => {
    try {
      const { token } = req.query;
      const { new_password, confirm_new_password } = req.body;

      console.log("TOKEN:", token);

      if (!token)
        return res.render("auth/reset-password", {
          message: "Invalid Token",
          token,
        });
      if (new_password != confirm_new_password)
        return res.render("auth/reset-password", {
          message: "Password doesn't match",
          token,
        });

      const payload = jwt.verify(token, JWT_KEY);

      const encryptedPassword = await bcrypt.hash(new_password, 10);

      const user = await User.update(
        { password: encryptedPassword },
        { where: { id: payload.user_id } }
      );
      //   if (!user)
      //     return res.render("auth/reset-password", {
      //       message: "Can't Update Password",
      //       token,
      //     });

      return res.render("auth/login", { error: null });
    } catch (error) {
      next(error);
    }
  },
};
