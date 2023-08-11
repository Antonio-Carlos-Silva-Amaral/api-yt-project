import express, { request, response } from 'express'
import { userRoutes } from './routes/user.routes';
import { videoRoutes } from './routes/videos.routes';
import { config } from 'dotenv';

config()

const app = express();

const cors = require('cors');

app.use(function(req,res,next){
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type,Accept");
    res.header('Access-Control-Allow-Methods', 'POST,GET,PATCH,DELETE,OPTIONS');
    next();
    
});

app.use(cors());


app.use(express.json());
app.use('/users',userRoutes);
app.use('/video',videoRoutes)

app.listen(4000);