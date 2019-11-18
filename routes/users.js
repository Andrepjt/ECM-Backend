var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');

var connection = require('../connection');
var config = require('../config.js');

var multer  = require('multer');
var path    = require('path');
var uploads = multer({dest: 'uploads'});

const fs = require('fs');

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
          var dt = new Date();

          var time = `${
            dt.getFullYear().toString().padStart(4, '0')}-${
                (dt.getMonth()+1).toString().padStart(2, '0')}-${
                  dt.getDate().toString().padStart(2, '0')} ${
                    dt.getHours().toString().padStart(2, '0')}:${
                      dt.getMinutes().toString().padStart(2, '0')}:${
                        dt.getSeconds().toString().padStart(2, '0')}`;

          var hashedPassword = bcrypt.hashSync(req.body.password, 8);
          let input = {
            email : req.body.email,
            username : req.body.username,
            password : hashedPassword,
            nama : req.body.nama,
            gender : req.body.gender,
            nik : req.body.nik,
            join_date : time
          }

          connection.query('INSERT INTO users SET ?', input, function (error, results, fields) {
              if(error){
                  console.log(error);
                  res.json({status : 'error', alert : 'try again'});
              } else {
                  let input = {
                    user_id : results.insertId,
                    poin_user : 10
                  }
                  connection.query('INSERT INTO poin SET ?', input, function (error, results, fields) {
                    res.json({status : 'success', alert: 'success'});
                  });
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
              res.json({ id : results[0].id, nik : results[0].nik, username: results[0].username, nama: results[0].nama,  join_date: results[0].join_date, status : 'success', auth: true, token: token });
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

router.get('/get_poin_value/:id', function(req, res, next) {
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
          connection.query('SELECT * FROM `users` left join `poin` on users.id = poin.user_id where users.id = ?', [req.params.id], function (error, results, fields) {
            try {
              let user = {
                id : results[0].user_id,
                email : results[0].email,
                username : results[0].username,
                nama : results[0].nama,
                nik : results[0].nik,
                gender : results[0].gender,
                poin_user : results[0].poin_user,
                join_date : results[0].join_date
              }
              return res.status(200).json(user);
            } catch(e) {
              res.status(403).json({
                success: false,
                message: 'Auth token is not supplied'
              });
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
                  res.json({status : 'success', category_qr : 'absen_ecm'});
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


router.post('/tambah_poin', function (req, res) {
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
                        res.json({status : 'error', alert: 'error'});
                      } else {
                        console.log('Success');
                        res.json({status : 'success', alert: 'error'});
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


router.post('/users/:id', function(req, res) {
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
          connection.query('SELECT * FROM users WHERE nik = ? ', [req.params.id], function(error, results, fields) {
            try {
              if(results.length == 0) {
                let info = {
                  status : 'error',
                  alert : 'nik not found!'
                }
                res.json(info);
              } else {
                res.json({
                  id : results[0].id,
                  email : results[0].email,
                  username : results[0].username,
                  nama : results[0].nama,
                  nik : results[0].nik,
                  category_qr : 'profile'
                });
              }
            } catch (e) {
              return res.status(404).send('404 Not Found!');
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


router.post('/upload_photo', function(req, res) {
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
          try {
            var storage = multer.diskStorage({
              destination: path.join('uploads'),
              filename: function (req, file, cb) {
                let data = cb(null, file.fieldname + '_' + Date.now() + path.extname(file.originalname));
              }
            });

            var upload = multer({ storage: storage }).single('file');

            upload(req, res, function (err) {
              if (err instanceof multer.MulterError) {
                res.json({status : "error"})
              } else if (err) {
                res.json({status : "error"})
              } else {
                let data = JSON.stringify(req.body, null, 2);
                let user = JSON.parse(data);
                let input = {
                  user_id : user.user_id,
                  path_of_file : req.file.filename
                }
                connection.query('INSERT INTO photo_profile SET ?', input, function(error, results, fields) {
                  try {
                    if(error){
                        console.log(error);
                        res.json({status : 'error'});
                    } else {
                        console.log('Success');
                        res.json({status : 'success'});
                    }
                  } catch (e) {
                    return res.status(404).send('404 Not Found!');
                  }
                });
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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


router.get('/check_photo_exist/:id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM photo_profile WHERE user_id = ?', [req.params.id], function(error, results, fields) {
              try {
                if(results.length == 0) {
                  res.json({
                    status : null,
                    message : 'photo is empty',
                    photo : null
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'photo is exist',
                    photo : results[0].path_of_file
                  });
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/delete_photo', function(req, res) {
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
          try {
            connection.query('SELECT * FROM photo_profile WHERE user_id = ?', [req.body.id], function(error, results, fields) {
              try {
                fs.unlink('uploads/'+results[0].path_of_file, (err) => {
                  if (err) throw err;
                  console.log('successfully deleted');
                });
                connection.query('DELETE FROM photo_profile where user_id = ?', [req.body.id], function(error, results, fields) {
                  res.json({
                    status : 'success',
                    message : 'photo has been deleted',
                    photo : null
                  });
                });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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


router.post('/add_log_poin', function(req, res) {
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
          try {
            connection.query('SELECT * FROM poin_scan_qr WHERE nik_scanner = ? AND nik_poin = ?', [req.body.nik_scanner, req.body.nik_poin], function(error, results, fields) {
              try {
                if(results.length == 0) {
                  let input = {
                    nik_scanner : req.body.nik_scanner,
                    nik_poin : req.body.nik_poin
                  }
                  connection.query('INSERT INTO poin_scan_qr SET ?', input, function(error, results, fields) {
                    res.json({ status: "success", message : "berhasil ditambahkan"});
                  });
                } else {
                  res.json({ status: "error", message : "Poin dari akun ini telah anda dapatkan"});
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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


router.get('/listing_info', function(req, res) {
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
          try {
            connection.query('SELECT * FROM information ORDER BY id DESC limit 5', function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/listing_event', function(req, res) {
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
          try {
            connection.query('SELECT * FROM event ORDER BY id DESC limit 1', function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/listing_event_all', function(req, res) {
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
          try {
            connection.query('SELECT * FROM event ORDER BY id DESC', function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/favorite_info/:id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM `favorite` LEFT JOIN `information` ON favorite.id_favorite = information.id where favorite.category_id = 1 AND favorite.user_id = ?', [req.params.id] ,function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch (e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/favorite_event/:id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM `favorite` LEFT JOIN `event` ON favorite.id_favorite = event.id where favorite.category_id = 2 AND favorite.user_id = ?', [req.params.id] ,function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/checking_favorite', function(req, res) {
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
          try {
            connection.query('SELECT * FROM `favorite` WHERE id_favorite = ? and category_id = ? and user_id = ?', [req.body.id_favorite, req.body.category_id, req.body.user_id], function(error, results, fields){
              try {
                if(results.length > 0) {
                  res.json({ status : 'success' });
                } else {
                  res.json({ status : 'error' });
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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
})

router.post('/post_info', function(req, res) {
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
          try {
            let input = {
              id_favorite : req.body.id_favorite,
              category_id : 1,
              user_id : req.body.user_id
            }
            connection.query('INSERT INTO favorite SET ?', input, function(error, results, fields) {
              try {
                res.json({ status: "success", message : "berhasil ditambahkan"});
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/post_event', function(req, res) {
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
          try {
            let input = {
              id_favorite : req.body.id_favorite,
              category_id : 2,
              user_id : req.body.user_id
            }
            connection.query('INSERT INTO favorite SET ?', input, function(error, results, fields) {
              try {
                res.json({ status: "success", message : "berhasil ditambahkan"});
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/delete_favorite', function(req, res) {
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
          try {
            connection.query('DELETE FROM favorite WHERE id_favorite = ? AND category_id = ? AND user_id = ?', [req.body.id_favorite, req.body.category_id, req.body.user_id], function(error, results, fields) {
              try {
                res.json({ status : 'success' });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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



router.post('/upload_timeline', function(req, res) {
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
          try {
            var storage = multer.diskStorage({
              destination: path.join('timeline_image'),
              filename: function (req, file, cb) {
                let data = cb(null, file.fieldname + '_' + Date.now() + path.extname(file.originalname));
              }
            });

            var upload = multer({ storage: storage }).single('photos');

            upload(req, res, function (err) {
              if (err instanceof multer.MulterError) {
                res.json({status : "error"})
              } else if (err) {
                res.json({status : "error"})
              } else {
                let data = JSON.stringify(req.body, null, 2);
                let user = JSON.parse(data);

                var dt = new Date();

                var time = `${
                  dt.getFullYear().toString().padStart(4, '0')}-${
                      (dt.getMonth()+1).toString().padStart(2, '0')}-${
                        dt.getDate().toString().padStart(2, '0')} ${
                          dt.getHours().toString().padStart(2, '0')}:${
                            dt.getMinutes().toString().padStart(2, '0')}:${
                              dt.getSeconds().toString().padStart(2, '0')}`;

                let input = {
                  user_id : user.user_id,
                  photos : req.file.filename,
                  caption : user.caption,
                  tanggal : time
                }
                connection.query('INSERT INTO timeline SET ?', input, function(error, results, fields) {
                  try {
                    if(error){
                      console.log(error);
                      res.json({status : 'error'});
                    } else {
                      console.log('Success');
                      res.json({status : 'success'});
                    }
                  } catch(e) {
                    return res.status(404).send('404 Not Found!');
                  }
                });
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/listing_timeline', function(req, res) {
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
          try {
            connection.query('SELECT * FROM timeline ORDER BY id DESC', function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/listing_timeline_own/:id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM timeline WHERE user_id = ? ORDER BY id DESC', [req.params.id], function(error, results, fields) {
              try {
                res.json({ data : results });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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




router.get('/data_personal/:id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM users WHERE id = ?', [req.params.id], function(error, results, fields) {
              try {
                if(error){
                  res.json({status : 'error', data : null});
                } else {
                  let user = {
                    id : results[0].id,
                    nik : results[0].nik,
                    nama : results[0].nama,
                    email : results[0].email,
                  }
                  res.json({status : 'success', data : user});
                }
              } catch (e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/delete_timeline', function(req, res) {
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
          try {
            connection.query('SELECT * FROM timeline WHERE id = ?', [req.body.id], function(error, results, fields) {
              try {
                fs.unlink('timeline_image/'+results[0].photos, (err) => {
                  if (err) throw err;
                  console.log('successfully deleted');
                });
                connection.query('DELETE FROM likes WHERE timeline_id = ?', [req.body.id], function(error, results, fields) {
                  try {
                    if(error) {
                      res.json({
                        status : 'error',
                        message : 'likes cannot delete',
                        photo : null
                      });
                    } else {
                      connection.query('DELETE FROM timeline WHERE id = ?', [req.body.id], function(error, results, fields) {
                        try {
                          if(error) {
                            res.json({
                              status : 'error',
                              message : 'photo cannot delete',
                              photo : null
                            });
                          } else {
                            res.json({
                              status : 'success',
                              message : 'photo has been deleted',
                              photo : null
                            });
                          }
                        } catch(e) {
                          return res.status(404).send('404 Not Found!');
                        }
                      });
                    }
                  } catch(e) {
                    return res.status(404).send('404 Not Found!');
                  }
                });
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/likes', function(req, res) {
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
          try {
            let input = {
              timeline_id : req.body.timeline_id,
              user_id : req.body.user_id
            }
            connection.query('INSERT INTO likes SET ?', input, function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot like right now',
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'Thanks',
                  });
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/dislike', function(req, res) {
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
          try {
            connection.query('DELETE FROM likes WHERE id = ?', [req.body.id], function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot delete right now',
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'data has been deleted',
                  });
                }
              } catch (e) {
                return res.status(404).send('404 Not Found!');
              }
            })
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/checking_like', function(req, res) {
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
          try {
            connection.query('SELECT * FROM likes WHERE user_id = ? AND timeline_id = ?', [req.body.user_id, req.body.timeline_id], function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot find data',
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'find data',
                    data : results
                  });
                }
              } catch (e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/likes_count/:timeline_id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM likes WHERE timeline_id = ?', [req.params.timeline_id], function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot find data',
                    count : 0
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'find data',
                    count : results.length
                  });
                }
              } catch (e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/likes_profile/:user_id', function(req, res) {
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
          try {
            connection.query('SELECT * FROM timeline LEFT JOIN likes ON timeline.id = likes.timeline_id WHERE timeline.user_id = ? AND likes.user_id IS NOT NULL', [req.params.user_id], function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot find data',
                    count : 0
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'find data',
                    count : results.length
                  });
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch (e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.post('/add_comments', function(req, res) {
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
          try {
            var dt = new Date();

            var time = `${
              dt.getFullYear().toString().padStart(4, '0')}-${
                  (dt.getMonth()+1).toString().padStart(2, '0')}-${
                    dt.getDate().toString().padStart(2, '0')} ${
                      dt.getHours().toString().padStart(2, '0')}:${
                        dt.getMinutes().toString().padStart(2, '0')}:${
                          dt.getSeconds().toString().padStart(2, '0')}`;

            let input = {
              timeline_id : req.body.timeline_id,
              user_id : req.body.user_id,
              comments : req.body.comments,
              waktu : time
            }
            connection.query('INSERT INTO comments SET ?', input, function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot add comment',
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'success add comment'
                  });
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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

router.get('/listing_comment/:timeline_id', function(req, res) {
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
          try {
            let token = req.headers['x-access-token'] || req.headers['authorization']; // Express headers are auto converted to lowercase
            if (token.startsWith('Bearer ')) {
              // Remove Bearer from string
              token = token.slice(7, token.length);
            }

            if (token) {
              connection.query('SELECT comments.id, comments.timeline_id, comments.user_id, comments.comments, comments.waktu, users.nama, photo_profile.path_of_file FROM comments LEFT JOIN users ON comments.user_id = users.id LEFT JOIN photo_profile ON photo_profile.user_id = comments.user_id WHERE comments.timeline_id = ? ORDER BY comments.id DESC',  [req.params.timeline_id], function(error, results, fields) {
                try {
                  if(error) {
                    res.json({
                      status : 'error',
                      message : 'cannot list comment',
                      data : null
                    });
                  } else {
                    res.json({
                      status : 'success',
                      message : 'list comment',
                      data : results
                    });
                  }
                } catch(e) {
                  return res.status(404).send('404 Not Found!');
                }
              });
            } else {
              return res.json({
                success: false,
                message: 'Auth token is not supplied'
              });
            }
          } catch(e) {
            return res.status(404).send('404 Not Found!');
          }
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


router.post('/add_laporkan', function(req, res) {
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
          try {
            var dt = new Date();

            var time = `${
              dt.getFullYear().toString().padStart(4, '0')}-${
                  (dt.getMonth()+1).toString().padStart(2, '0')}-${
                    dt.getDate().toString().padStart(2, '0')} ${
                      dt.getHours().toString().padStart(2, '0')}:${
                        dt.getMinutes().toString().padStart(2, '0')}:${
                          dt.getSeconds().toString().padStart(2, '0')}`;

            let input = {
              content_id : req.body.content_id,
              desc : req.body.desc,
              tanggal : time,
              user_id : req.body.user_id
            }

            connection.query('INSERT INTO laporan SET ?', input, function(error, results, fields) {
              try {
                if(error) {
                  res.json({
                    status : 'error',
                    message : 'cannot add laporan'
                  });
                } else {
                  res.json({
                    status : 'success',
                    message : 'success add laporan'
                  });
                }
              } catch (e) {
                return res.status(404).send('404 Not Found!');
              }
            })
          } catch (e) {
            return res.status(404).send('404 Not Found!');
          }
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


// router.get('/users/page/:number', function(req, res) {
//   try {
//     connection.query('SELECT * FROM users', function(error, results, fields) {
//       try {
//         if(error) {
//           res.json({
//             status : 'error',
//             message : 'cannot list users',
//             data : null
//           });
//         } else {
//           const pageCount = Math.ceil(results.length / 10);
//           let page = parseInt(req.params.number);
//           if (!page) { page = 1;}
//           if (page > pageCount) {
//             page = pageCount
//           }
//           res.json({
//             page: page,
//             pageCount: pageCount,
//             users: results.slice(page * 10 - 10, page * 10)
//           });
//         }
//       } catch (e) {
//         return res.status(404).send('404 Not Found!');
//       }
//     });
//
//
//
//
//   } catch(e) {
//     return res.status(404).send('404 Not Found!');
//   }
// });

router.get('/users/search/:nama', function(req, res) {
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
          try {
              connection.query("SELECT users.id, users.nik, users.email, users.nama, users.gender, users.join_date, photo_profile.path_of_file FROM users LEFT JOIN photo_profile ON users.id = photo_profile.user_id WHERE users.nama LIKE ?", ['%'+req.params.nama+'%'], function(error, results, fields) {
                try {
                  if(error) {
                    res.json({
                      status : 'error',
                      message : 'cannot list users',
                      data : null
                    });
                  } else {
                    res.json({
                      status : 'success',
                      message : 'success list users',
                      data : results
                    });
                  }
                } catch (e) {
                  return res.status(404).send('404 Not Found!');
                }
              });
          } catch (e) {
            return res.status(404).send('404 Not Found!');
          }
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


router.post('/update_pass', function(req, res) {
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
          try {
            var hashedPassword = bcrypt.hashSync(req.body.password, 8);
            connection.query('UPDATE users SET password = ? WHERE id = ?', [ hashedPassword, req.body.id], function (error, results, fields) {
              try {
                if(error){
                    console.log(error);
                    res.json({status : 'error'});
                } else {
                    console.log('Success');
                    res.json({status : 'success'});
                }
              } catch(e) {
                return res.status(404).send('404 Not Found!');
              }
            });
          } catch (e) {
            return res.status(404).send('404 Not Found!');
          }
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



module.exports = router;
