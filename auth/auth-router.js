const router = require('express').Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')

const Users = require('./auth-model');

const secrets = require('../database/config/secrets')

router.post('/register', (req, res) => {
  // implement registration
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 8);
  user.password = hash;

  Users.add(user)
    .then(saved => {
      const token = generateToken(user);
      res.status(201).json({username: user.username, payload: token});
    })
    .catch(error => {
      console.log(error);
      res.status(500).json(error);
    })
});

router.post('/login', (req, res) => {
  let {username, password} = req.body;
  Users.findBy({username})
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);
        res.status(200).json({payload: token});
      } else {
        res.status(401).json({message: 'Invalid Credentials'});
      }
    })
    .catch(error => {
      console.log(error);
      res.status(500).json(error);
    })
});

function generateToken(user) {
  const payload = {
    user
  };
  const options = {
    expiresIn: '1d',
  };

  return jwt.sign(payload, secrets.jwtSecret, options);
};

module.exports = router;
