const express = require("express");
const router = express();
const handler = require("../handlers");

router.get("/auth/register", handler.auth.signUp);
router.post("/auth/register", handler.auth.register);

router.get("/auth/login", handler.auth.signIn);
router.post("/auth/login", handler.auth.login);

router.get("/auth/forgot-password", handler.auth.forgotPasswordView);
router.post("/auth/forgot-password", handler.auth.forgotPassword);

router.get("/auth/reset-password", handler.auth.resetPasswordView);
router.post("/auth/reset-password", handler.auth.resetPassword);

module.exports = router;
