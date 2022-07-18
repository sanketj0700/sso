// modules
const express = require("express");
const jwt = require("jsonwebtoken");
const jose = require("jose");
const path = require("path");
const cookieParser = require('cookie-parser');

// dotenv configuration
require("dotenv").config();

// expres app setup
const app = express();
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET_KEY))


// users
const users = [
  {
    username: "user1",
    email : "user1@trial.com",
    password: "user1password",
    role: "admin"
  },
  {
    username: "user2",
    email : "user2@trial.com",
    password: "user2password",
    role: "user"
  },
  {
    username: "user3",
    email : "user3@trial.com",
    password: "user3password",
    role: "user"
  }
];


app.use(express.static(path.join(__dirname, '/client-microsite/dist/client-microsite/')))
app.set('view engine', 'pug');


app.get('/', async(req, res) => {
  try{
    res.sendFile(path.join(__dirname,'/client-microsite/dist/client-microsite/index.html'));
    res.end();
  } catch(err) {
    console.log(err);
    res.status(500).end();
  }
});


app.post('/login', async(req, res) => {
  try{
    const { email, password, role } = req.body;
    const usersFound = users.filter(user => {
      return (user.email===email && user.password===password && user.role===role);
    })

    console.log(usersFound);
    console.log(email, password, role);

    if(usersFound.length===1) {
      const user = {
        email: email,
        username: usersFound[0].username,
        role: role
      }

      const pk = `-----BEGIN PRIVATE KEY-----
      MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsKCniyca2pJp12kE
      wrImdsrVsCK6mTp3wMbtwFDtuOChRANCAARHB6M1sQ7iDbkKf+VUehK3UKnPERxB
      uvDft/iPBbswxnXdB/5guWyqcnvYOQ4zmgE289b67VggphiNgvYgbEH3
      -----END PRIVATE KEY-----`;

      const privateKey = await jose.importPKCS8(pk, 'ES256');

      // with encrypted payload
      const token = await new jose.SignJWT({})
                                  .setProtectedHeader({ ...user, alg: 'ES256' })
                                  .setIssuedAt(Math.floor(Date.now()/1000)+10)
                                  .setIssuer('http://localhost:3000')
                                  .setAudience('http://localhost:3000')
                                  .setExpirationTime('2h')
                                  .sign(privateKey);
      
      // without encrypted payload
      // const token = await new jose.SignJWT({user})
      //                             .setProtectedHeader({ alg: 'ES256' })
      //                             .setIssuedAt(Math.floor(Date.now()/1000)+10)
      //                             .setIssuer('http://localhost:3000')
      //                             .setAudience('http://localhost:3000')
      //                             .setExpirationTime('2h')
      //                             .sign(privateKey);

      // const { payload, protectedHeader } = await jose.jwtVerify(token, privateKey, {
      //                                               issuer: "http://localhost:3000", // issuer
      //                                               audience: "http://localhost:3000", // audience
      //                                             }); 
      

      // const token = jwt.sign({user: user, iat: (Math.floor(Date.now()/1000)+10) }, process.env.JWT_PRIVATE_KEY, { algorithm: 'ES256', expiresIn: '2h', issuer: 'http://localhost:3000', audience: 'https://localhost:3000' });
      res.cookie('micrositeAuthenticationCookie', token, { signed: true, sameSite: 'strict', secure: true, httpOnly: true, maxAge: 60*60*1000 });
      res.end();

    } else if(usersFound.length===0) {
      res.status(400).json({message: "Invalid credentials..."}).end();
    }

  } catch(err) {
    console.log(err);
    res.status(500).end();
  }
})


app.get('/authenticate', async(req, res) => {
  try {
    console.log(req.query);
    token = req.signedCookies['micrositeAuthenticationCookie'];

    const pk = `-----BEGIN PRIVATE KEY-----
    MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgsKCniyca2pJp12kE
    wrImdsrVsCK6mTp3wMbtwFDtuOChRANCAARHB6M1sQ7iDbkKf+VUehK3UKnPERxB
    uvDft/iPBbswxnXdB/5guWyqcnvYOQ4zmgE289b67VggphiNgvYgbEH3
    -----END PRIVATE KEY-----`;

    const privateKey = await jose.importPKCS8(pk, 'ES256');

    const { payload, protectedHeader } = await jose.jwtVerify(token, privateKey, {
                                                  issuer: "http://localhost:3000", // issuer
                                                  audience: "http://localhost:3000", // audience
                                                });

    if(payload) {
      res.redirect(req.query.redirect_url + "?user=" + JSON.stringify(payload));
    } else {
      res.status(400).end();
    }
  } catch(err) {
    console.log(err);
    res.status(400).end();
  }
})


// serving app
const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, (err) => {
  if(!err) {
    console.log(`Server listening on port ${PORT}`);
  } else {
    console.log(`Failed starting up the server`);
  }
})