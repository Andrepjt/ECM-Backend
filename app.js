var express = require('express');




//routers
var users = require('./routes/users')

var app = express();

app.use(function(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});



//url
app.use('/', users);

//public
var publicDir = require('path').join(__dirname,'uploads');
app.use('/photo_profile', express.static(publicDir));

var publicDirNews = require('path').join(__dirname,'news_image');
app.use('/news_image', express.static(publicDirNews));

var publicDirInfos = require('path').join(__dirname,'event_image');
app.use('/event_image', express.static(publicDirInfos));




app.use(function(req, res, next) {
  res.status(404);

  if(req.accepts('json')) {
    res.send({ error : 'Not Found!' });
    return;
  }

  res.type('txt').send('Not Found!');
});



app.set('port', (process.env.PORT || 3000));



app.listen(app.get('port'), function() {
  console.log('Server is running');
});
