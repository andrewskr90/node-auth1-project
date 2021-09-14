const express = require('express')
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')
const { checkUsernameFree, checkUsernameExists, checkPasswordLength } = require('./auth-middleware')
// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = express.Router()

router.post('/register', checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const hash = bcrypt.hashSync(password, 8)
    const newUser = { username, password: hash }
    const user = await User.add(newUser)
 
    res.status(200).json(user)
  } catch (err) {
    next(err)
  }
})

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post('/login', checkUsernameExists, async (req, res, next) => {
  try {
    const { username, password } = req.body
    const [existingUser] = await User.findBy({ username })
    // check if username in db
    // recreate hash from password
    // if username exists, AND hash matches the one in db
    // THEN START A SESSION WITH THE HELP OF A LIB expresse-session

    if (existingUser && bcrypt.compareSync(password, existingUser.password)) {
      // here this means user exists AND credentials good
      console.log('starting session!!!')
      req.session.user = existingUser
      res.json({
        message: `/welcome ${existingUser.username}/i`
      })
    } else {
      next({ status: 401, message: '/invalid credentials/i' })
    }
  } catch (err) {
    next(err)
  }
})
/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.get('/logout', (req, res ) => {
    if (req.session.user) {
      req.session.destroy(err => {
        if (err) {
          res.json({
            message: 'err, you cannot leave'
          })
        } else {
          res.json({
            message: '/logged out/i'
          })
        }
      })
    } else {
      res.json({
        message: '/no session/i' 
      })
    }
  })

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router