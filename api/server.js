const path = require('path')
const express = require("express");
const helmet = require("helmet");
const session = require('express-session')
const cors = require("cors");
const store = require('connect-session-knex')(session)

/**
  Do what needs to be done to support sessions with the `express-session` package!
  To respect users' privacy, do NOT send them a cookie unless they log in.
  This is achieved by setting 'saveUninitialized' to false, and by not
  changing the `req.session` object unless the user authenticates.

  Users that do authenticate should have a session persisted on the server,
  and a cookie set on the client. The name of the cookie should be "chocolatechip".

  The session can be persisted in memory (would not be adecuate for production)
  or you can use a session store like `connect-session-knex`.
 */

const server = express();

server.use(express.static(path.join(__dirname, '../client')));
// server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session({
  name: 'chocolatechip', // the name of the cookie the server will place on client (session id)
  secret: 'nobody tosses a dwarf!', // put this in the environment, not the code!!!!
  cookie: {
    maxAge: 1 * 24 * 60 * 60 * 1000,
    secure: false, // in prod, it should be true: ONLY HTTPS!!!!!!!!
  },
  httpOnly: true, // don't let JS code access cookies. Browser extensions run JS code on your browser!
  resave: false, // IGNORE, some libs need this
  saveUninitialized: false, // only save a session if user approves
  // PERSISTING SESSIONS TO THE DATABASE!!!
  store: new store({
    knex: require('../data/db-config.js'), // configured instance of knex
    tablename: 'sessions', // table that will store sessions inside the db, name it anything you want
    sidfieldname: 'sid', // column that will hold the session id, name it anything you want
    createtable: true, // if the table does not exist, it will create it automatically
    clearInterval: 1000 * 60 * 60, // time it takes to check for old sessions and remove them from the database to keep it clean and performant
  }),
}));

server.get("/", (req, res) => {
  res.json({ api: "up" });
});

server.use((err, req, res, next) => { // eslint-disable-line
  res.status(err.status || 500).json({
    message: err.message,
    stack: err.stack,
  });
});

module.exports = server;
