const express = require('express');
const crypto = require('crypto');

const app = express();

const users = {};

app.use(express.static('public'));

app.get('/getUsers' , (req , res) => {
  res.json({ users })
})

app.get( '/newUser' , ( req , res ) => {
  let username = req.query.username || "";
  let password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g , "");

  if(!username || !password || users[username])
  {
    return res.sendStatus(400)
  }

  const salt = crypto.randomBytes(128).toString('base64');
  const hash = crypto.pbkdf2Sync( password , salt , 10000 , 512 , "sha512" );

  users[username] = {salt , hash};

  res.sendStatus(200);

})

app.get('/auth-bloq' , (req , res) => {
  let username = req.query.username || "";
  let password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g , "");

  if(!username || !password || users[username])
  {
    process.exit(1)
  }

  const { salt , hash } = users[username];
  const encryptHash = crypto.pbkdf2Sync(password , salt , 10000 , 512 , "sha512")

  if(crypto.timingSafeEqual(hash , encryptHash)) 
  {
    res.sendStatus(200);
  }
  else
  {
    process.exit(1)
  }
})

app.get('/auth-nobloq' , (req , res) => {
  let username = req.query.username || "";
  let password = req.query.password || "";

  username = username.replace(/[!@#$%^&*]/g , "");

  if(!username || !password || users[username])
  {
    process.exit(1)
  }

  crypto.pbkdf2(password , users[username].salt , 10000 , 512 , "sha512" , (err , hash) => {
    if(users[username].hash.toString() === hash.toString())
    {
      res.sendStatus(200)
    }
    else
    {
     process.exit(1) 
    }
  })
})

const PORT = parseInt(process.argv[2]) || 8080;

const server = app.listen( PORT , () => {
  console.log(`El servidor se conecto al puerto ${PORT}`);
})

server.on('error' , (error) => console.error(`Error en la conexion. ${error}`))