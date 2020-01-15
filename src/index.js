const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

require('dotenv').config({path: 'variables.env'});
const createServer = require('./createServer');
const db = require('./db');

const server = createServer();

// express middleware to handle cookies (JWT)
// middleware sits between reciving req and sending response
server.express.use(cookieParser());

// decode the JWT so we can get the user ID on each request
server.express.use((req,res,next)=> {
    const {token} = req.cookies;
    if(token){
        const {userId} = jwt.verify(token, process.env.APP_SECRET);
        // put the userId onto the req for future requests to access
        req.userId = userId;
    }
    next();
})

// TODO use express middleware to populate user

server.start({
    cors: {
        credentials: true,
        origin: process.env.FRONTEND_URL
    }
}, deets => {
    console.log('server running on port http://localhost:'+deets.port)
})