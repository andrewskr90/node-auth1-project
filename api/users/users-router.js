const express = require('express')
const { restricted } = require('../auth/auth-middleware')

const User = require('./users-model')

const router = express.Router()
// Require the `restricted` middleware from `auth-middleware.js`. You will need it here!
router.get('/', restricted, async (req, res, next) => {
  try {
    return User.find()
  } catch (err) {
    next(err)
  }
})

/**
  [GET] /api/users

  This endpoint is RESTRICTED: only authenticated clients
  should have access.

  response:
  status 200
  [
    {
      "user_id": 1,
      "username": "bob"
    },
    // etc
  ]

  response on non-authenticated:
  status 401
  {
    "message": "You shall not pass!"
  }
 */
router.use((err, req, res, next) => {
  res.status(err.status).json(err.message)
})


// Don't forget to add the router to the `exports` object so it can be required in other modules
