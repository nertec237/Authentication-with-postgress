import express  from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt, { hash } from 'bcrypt';
import jwt from "jsonwebtoken";



const {Pool}=pg;
const app = express();
const port = 3004;

const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "userDB",
    password: "nerman",
    port: 5432,
  });




    
//middleware
app.use(bodyParser.urlencoded({ extended:true}));

app.use(express.static("public"));

app.post("/registration",async(req,res)=>{
    const {usersname,usersemail,userslevel,userspassword}=req.body
    const hashpassword = await  bcrypt.hash(userspassword,10);
    try{ 
        pool.query('INSERT INTO userInformation (username,useremail,userlevel,userpassword) VALUES($1,$2,$3,$4) RETURNING*',[usersname,usersemail,userslevel,hashpassword])
        res.status(201).json("Account Created");
    }catch(err){
        res.status(401).json({error:"already exist"});
    }

});

app.post("/sign",async(req,res)=>{
    const {usersemail,usersignpassword}=req.body
    const result = await pool.query('SELECT * FROM userinformation WHERE useremail=$1',[usersemail]);

  const user = result.rows[0];

  if (user && await bcrypt.compare(usersignpassword, user.userpassword)) {
    console.log(usersignpassword , user.userpassword);
    const token =  jwt.sign(
      { id: user.id, email: user.email },
      'your_jwt_secret',
      { expiresIn: '1h' }
    );
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid email or password' });
  }
});

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'].split('')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, 'your_jwt_secret', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route!', user: req.user });
});



app.get("/",(req,res)=>{
    res.render("index.ejs")
});
app.get("/registration",(req,res)=>{
    res.render("registration.ejs")
});
app.get("/services",(req,res)=>{
    res.render("services.ejs")
});


app.get("/aboutus",(req,res)=>{
    res.render("aboutus.ejs")
});
app.get("/contact",(req,res)=>{
    res.render("contact.ejs")
});

app.get("/signin",(req,res)=>{
    res.render("signin.ejs")
});


app.listen(port,()=>{
    console.log(`Server is running at http://localhost:${port}`)
})