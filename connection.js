var mysql = require('mysql');

var connection = mysql.createConnection({
  host: "db4free.net",
  user: "ecmlala",
  password: "andrearif25",
  database: "ecmlala"
});

connection.connect(function (err){
    if(err) throw err;
});

module.exports = connection;
