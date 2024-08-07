const router = require("express").Router();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // Use this secret
const User = require("../users/users-model");

// Helper function to create a token
function buildToken(user) {
  const payload = {
    subject: user.user_id, // subject is typically the user_id
    username: user.username,
    role_name: user.role_name,
  };

  const options = {
    expiresIn: "1d", // Token expiration time
  };

  return jwt.sign(payload, JWT_SECRET, options);
}

// Register endpoint
router.post("/register", validateRoleName, async (req, res, next) => {
  const { username, password } = req.body;
  const role_name = req.role_name || "student";
  const hash = bcrypt.hashSync(password, 8);
  User.add({ username, password: hash, role_name })
    .then((newUser) => {
      res.status(201).json(newUser);
    })
    .catch(next);
});

// Login endpoint
router.post("/login", checkUsernameExists, async (req, res, next) => {
  try {
    if (bcrypt.compareSync(req.body.password, req.user.password)) {
      const token = buildToken(req.user);
      res.status(200).json({
        message: `${req.user.username} is back!`,
        token,
      });
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
