const express = require("express");

const router = express.Router();

const {login, register, refToken} = require("../controllers/authController");


router.route("/register").post(register);
router.route("/login").post(login);
router.route("/refresh-token").post(refToken)

module.exports = router;