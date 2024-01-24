const express = require("express");
require("dotenv").config();
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cookiePraser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const ws = require("ws");


// database models
const User = require("./models/User.js");
const Message = require("./models/Message.js");


// app startups and some constnts
const app = express();
const jwtSec = process.env.JWT_SEC;
const bcryptSalt = bcrypt.genSaltSync(10);

// middlewares
app.use(express.json());
app.use(cookiePraser());
app.use(cors({
    credentials : true,
    origin : "https://mern-chat-vert.vercel.app",
}));

const port = process.env.PORT || 8000

// mongodb connection
mongoose
    .connect(process.env.MONGO_URL)
    .then((e)=>{console.log("mongo db connected")});



// test routes
app.get("/test",(req,res)=>{
    res.json({message:"successful response"});
})


app.get("/users",async (req,res)=>{
    // no find condition but the projection is on
    const users = await User.find({},{'_id':1, username:1});
    return res.json(users);
})


app.get("/profile",(req,res)=>{
    //console.log(req);
    const token = req.cookies?.token;
    if(!token){
        return res.status(202).json({message : "token is not found"});
    }
    const payLoad = jwt.verify(token,jwtSec);
    //console.log(payLoad)
    if(!payLoad){
        return res.json({message:"user token is not verified"});
    }
    const {userId,username} = payLoad
    return res.status(207).json({
        userId,
        username,
    })
})


//sending the messages where sender or reciever is userid and we 
app.get("/messages/:userId",async (req,res)=>{
    // this is the userid of chat
    const wantedUser = req.params.userId;
    // we need the userid of requester or our userid
    // will get it from cookie
    const token = req.cookies?.token;
    if(!token){
        return res.status(202).json({message : "token is not found"});
    }
    const payLoad = jwt.verify(token,jwtSec);
    if(!payLoad){
        return res.json({message:"user token is not verified"});
    }
    const {userId,username} = payLoad

    const messages = await Message.find({
        sender:{$in:[userId,wantedUser]},
        recipient : {$in:[userId,wantedUser]}
    }).sort({createdAt:1});

    return res.json(messages);
})


// post route for login purpose
app.post("/login", async (req,res)=>{
    const {username,password} = req.body;

    const foundUser = await User.findOne({username});
    if(!foundUser){
        return res.json({message : "no user found"});
    }
    const iscorrect = await bcrypt.compare(password,foundUser.password);
    if(iscorrect){
        const token = await jwt.sign({userId : foundUser._id, username:foundUser.username},jwtSec);
        res.cookie("token",token,{sameSite:'none', secure:true}).status(201).json({
            id : foundUser._id,
            username
        });
    }
    else{
        return res.json({message: "wrong password"});
    }
})


app.post("/logout",(req,res)=>{
    res.clearCookie("token").json({message : "okkk"});
})


// post route on register
app.post("/register",async (req,res)=>{
    const {username, password} = req.body;

    if(!username || !password){
        console.log("invalid entry");
        return res.json(200);
    }
    const checkuser =  await User.findOne({username});

    // pending work when already registed user wanted to do register again
    if(checkuser){
        console.log("duplicate entry");
        return res
    }

    const hashedpassword = await bcrypt.hash(password,bcryptSalt);
    const createdUser = await User.create({
        username:username,
        password:hashedpassword,
    })

    const token = await jwt.sign({userId : createdUser._id, username:username},jwtSec);

    res.cookie("token",token,{sameSite:'none', secure:true}).status(201).json({
        id : createdUser._id,
        username
    });
})


const server = app.listen(port,()=>{
console.log("server started successfully");
})


const wsServer = new ws.WebSocketServer({server:server});

wsServer.on("connection",(connection,req)=>{


    function notifyAboutOnlinePeople (){
        // notify everyone about online people
        // when someone connected
        [...wsServer.clients].map(client =>{
            client.send(JSON.stringify({
                online : [...wsServer.clients].map(c=>({userId : c.userId,username:c.username}))
                }
            ))
        });
    }

    // when user goes offline we need to refresh for update
    // to solve that will is isAlive and setinterval
    // for that we need to ping the connection
    connection.isAlive = true;
    
    connection.timer = setInterval(()=>{
        connection.ping();
        connection.deathTimer = setTimeout(() => {
            connection.isAlive = false;
            clearInterval(connection.timer);
            connection.terminate();
            notifyAboutOnlinePeople();
        }, 1000);
        //console.log("i got dead");
    },5000);


    connection.on('pong',()=>{
        clearTimeout(connection.deathTimer);
    })


    const cookies = req.headers.cookie;
    if(cookies){
        const tok = cookies.split(';').find(str=>str.startsWith("token="));
        if(tok){
            // finding the current user 
            const finalToken = tok.split('=')[1];
            if(finalToken){
                const payLoadx = jwt.verify(finalToken,jwtSec);
                 const {userId, username} = payLoadx;
                connection.userId = userId;
                connection.username = username;
                console.log("connected user ",username);
            }
        }
    }
    
    connection.on('message', async (message)=>{
        // getting the message
        const messageData = JSON.parse(message.toString());
        const {recipient, text} = messageData;


        // sending the message if recipient user exists
        if(recipient && text){
            // creating entry in message collections
            const messageDoc = await Message.create({
                sender : connection.userId,
                recipient,
                text,
            });
            
            // sending message to all the valid users
            [...wsServer.clients]
                .filter(c => c.userId === recipient)
                .forEach(c => c.send(JSON.stringify({
                    text, 
                    sender : connection.userId,
                    _id : messageDoc._id,
                    recipient,
                })));
        }
    });

    // calling function
    notifyAboutOnlinePeople();

})

wsServer.on('close', (data)=>{
    console.log("dissconnected",data)
})
