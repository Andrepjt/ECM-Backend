var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');

var connection = require('../connection');
var config = require('../config.js');



let data = [
  { id : 1,
    username : 'arif1234',
    password : 'password1234',
    nama : 'Arif',
    gender : 'Pria',
    age : 26
  }, {
    id : 2,
    username : 'jack1234',
    password : 'password1234',
    nama : 'Jack',
    gender : 'Pria',
    age : 26
  }
]


router.use(express.json());
router.use(bodyParser.urlencoded({extended : false}));



router.post('/register', function(req, res) {
  try {
    res.status(200);
    if(req.body.email.trim() == "") {
      let info = {
        status : 'error',
        alert : 'require email'
      }
      res.json(info);
    } else if(req.body.username.trim() == "") {
      let info = {
        status : 'error',
        alert : 'require username'
      }
      res.json(info);
    } else if(req.body.password.trim() == "") {
      let info = {
        status : 'error',
        alert : 'require password'
      }
      res.json(info);
    } else if(req.body.nama.trim() == "") {
      let info = {
        status : 'error',
        alert : 'require nama'
      }
      res.json(info)
    } else if(req.body.nik.trim() == "") {
      let info = {
        status : 'error',
        alert : 'require nik'
      }
      res.json(info)
    } else {
      connection.query('SELECT * FROM `users` WHERE `username` = ?', [req.body.username], function (error, results, fields) {
                                  if(results.length > 0) {
                                    let info = {
                                          status : 'error',
                                          alert : 'username has been used!, please trying another username.'
                                        }
                                        res.json(info);
                                  } else if(results.length == 0) {
                                    var hashedPassword = bcrypt.hashSync(req.body.password, 8);
                                    let input = {
                                      email : req.body.email,
                                      username : req.body.username,
                                      password : hashedPassword,
                                      nama : req.body.nama,
                                      gender : req.body.gender,
                                      nik : req.body.nik
                                    }

                                    connection.query('INSERT INTO users SET ?', input, function (error, results, fields) {
                                        if(error){
                                            console.log(error);
                                            res.json({status : 'error'});
                                        } else {
                                            console.log('Success');
                                            res.json({status : 'success'});
                                        }
                                    });
                                  }
                                });

    }
  } catch (e) {
    res.status(404);
  }
});

router.post('/login', function(req, res) {
  let user = {
    username : req.body.username,
    password : req.body.password,
  }
  try {
    res.status(200);
    if(user.username == "" || user.username == null) {
      let info = {
        status : 'error',
        alert : 'require username'
      }
      res.json(info);
    } else if(user.password == "" || user.password == null) {
      let info = {
        status : 'error',
        alert : 'require username'
      }
      res.json(info);
    } else {
      let input = {
        username : req.body.username,
        password : req.body.password,
      }
      connection.query('SELECT * FROM `users` WHERE `username` = ?', [input.username], function (error, results, fields) {
        try {
          if(results.length == 0) {
            let info = {
                  status : 'error',
                  alert : 'username not found!'
                }
                res.json(info);
          } else if(results.length > 0) {
            var passwordIsValid = bcrypt.compareSync(req.body.password, results[0].password);
            if(!passwordIsValid) {
              res.json({status : 'error', alert: 'password is wrong!'});
            } else {
              var token = jwt.sign({ id : results[0].id, username: results[0].username }, config.secret, {
                expiresIn: 86400
              });
              res.json({ id : results[0].id, username: results[0].username, nama: results[0].nama,  status : 'success', auth: true, token: token });
            }
          }
        } catch (e) {
          console.log('Error');
        }
      });
    }
  } catch (e) {
    res.status(404);
  }
});



router.get('/profile', function(req, res, next) {
  try {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token.startsWith('Bearer ')) {
      // Remove Bearer from string
      token = token.slice(7, token.length);
    }

    if (token) {
      jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
          return res.status(200).json({
            success: false,
            message: 'Token is not valid'
          });
        } else {
          connection.query('SELECT * FROM `users` WHERE `username` = ?', [decoded.username], function (error, results, fields) {
            let user = {
              id : results[0].id,
              email : results[0].email,
              username : results[0].username,
              nama : results[0].nama,
              nik : results[0].age,
              gender : results[0].gender
            }
            return res.status(200).json(user);
            next();
          });

        }
      });
    } else {
      return res.json({
        success: false,
        message: 'Auth token is not supplied'
      });
    }
  } catch (e) {
    res.status(403).json({
      success: false,
      message: 'Auth token is not supplied'
    });
  }
});

router.get('/get_poin_value', function(req, res, next) {
  try {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token.startsWith('Bearer ')) {
      // Remove Bearer from string
      token = token.slice(7, token.length);
    }

    if (token) {
      jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
          return res.status(200).json({
            success: false,
            message: 'Token is not valid'
          });
        } else {
          connection.query('SELECT * FROM `users` left join `poin` on users.id = poin.user_id where users.id = ?', [decoded.id], function (error, results, fields) {
            let user = {
              id : results[0].user_id,
              email : results[0].email,
              username : results[0].username,
              nama : results[0].nama,
              nik : results[0].nik,
              gender : results[0].gender,
              poin_user : results[0].poin_user
            }
            return res.status(200).json(user);
            next();
          });
        }
      });
    } else {
      return res.json({
        success: false,
        message: 'Auth token is not supplied'
      });
    }
  } catch (e) {
    res.status(403).json({
      success: false,
      message: 'Auth token is not supplied'
    });
  }
});


router.post('/absen_ecm', function(req, res) {
  try {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token.startsWith('Bearer ')) {
      // Remove Bearer from string
      token = token.slice(7, token.length);
    }

    if (token) {
      jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
          return res.status(200).json({
            success: false,
            message: 'Token is not valid'
          });
        } else {
          let input = {
            user_id : req.body.user_id,
          }
          connection.query('INSERT INTO absensi_ecm SET ?', input, function (error, results, fields) {
              if(error){
                  console.log(error);
                  res.json({status : 'error'});
              } else {
                  console.log('Success');
                  res.json({status : 'success'});
              }
          });

        }
      });
    } else {
      return res.json({
        success: false,
        message: 'Auth token is not supplied'
      });
    }
  } catch(e) {
    res.status(403).json({
      success: false,
      message: 'Auth token is not supplied'
    });
  }
});

router.post('/transfer_poin', function(req, res) {
  try {
    let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
    if (token.startsWith('Bearer ')) {
      // Remove Bearer from string
      token = token.slice(7, token.length);
    }

    if (token) {
      jwt.verify(token, config.secret, (err, decoded) => {
        if (err) {
          return res.status(200).json({
            success: false,
            message: 'Token is not valid'
          });
        } else {
          connection.query('SELECT * FROM users WHERE nik = ? ', [req.body.user_id], function(error, results, fields) {
            try {
              if(results.length == 0) {
                let info = {
                  status : 'error',
                  alert : 'nik not found!'
                }
                res.json(info);
              } else {
                connection.query('SELECT * FROM `users` left join `poin` on users.id = poin.user_id where users.id = ?', [results[0].id], function (error, results, fields) {
                  var a = parseInt(req.body.poin_user);
                  var b = parseInt(results[0].poin_user);
                  var c = a + b;
                  connection.query('UPDATE poin SET poin_user = ? WHERE user_id = ?', [ c , results[0].user_id], function (error, results, fields) {
                      if(error){
                          console.log(error);
                          res.json({status : 'error'});
                      } else {
                        connection.query('SELECT * FROM `users` left join `poin` on users.id = poin.user_id where users.id = ?', [req.body.pengirim_id], function(error, results, fields) {
                          var a = parseInt(results[0].poin_user);
                          var b = parseInt(req.body.poin_user);
                          var c = a - b;
                          connection.query('UPDATE poin SET poin_user = ? WHERE user_id = ?', [ c , results[0].user_id], function (error, results, fields) {
                              if(error){
                                  console.log(error);
                                  res.json({status : 'error'});
                              } else {
                                  console.log('Success');
                                  res.json({status : 'success'});
                              }
                          });
                        });
                      }
                  });
                });

              }
            } catch (e) {
              console.log('Error');
            }
          });

        }
      });
    } else {
      return res.json({
        success: false,
        message: 'Auth token is not supplied'
      });
    }

  } catch (e) {
    res.status(403).json({
      success: false,
      message: 'Auth token is not supplied'
    });
  }
});


router.get('/users/:id', function(req, res) {
  connection.query('SELECT * FROM users WHERE nik = ? ', [req.params.id], function(error, results, fields) {
    try {
      if(results.length == 0) {
        let info = {
          status : 'error',
          alert : 'nik not found!'
        }
        res.json(info);
      } else {
        let user = {
          id : results[0].id,
          email : results[0].email,
          username : results[0].username,
          nama : results[0].nama,
          nik : results[0].nik
        }
        res.json(user);
      }
    } catch (e) {
      return res.status(404).send('404 Not Found!');
    }
  })
});




// router.get('/users/:id', function(req, res) {
//   let get = data.find(c => c.id === parseInt(req.params.id));
//   if(!get) return res.status(404).send('404 Not Found!');
//   res.json(get);
// });


module.exports = router;
