const express = require('express');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const app = express();

app.use(express.json());

const users = [
    {
        id: 1,
        username: 'John',
        password: '123456',
        isAdmin: true,
    },
    {
        id: 2,
        username: 'Jane',
        password: '123456',
        isAdmin: false,
    }
]

const generateAccessToken =(user)=> {
    const accessToken = jwt.sign({
        userId: user.id,
        isAdmin: user.isAdmin
    }, 'mySecretKey', {expiresIn: '1h'});

    return accessToken;
}

const generateRefreshToken =(user)=> {
    const refreshToken = jwt.sign({
        userId: user.id,
        isAdmin: user.isAdmin
    }, 'myRefreshSecretKey');

    return refreshToken;
}

const verify =(req, res, next)=>{
    const authHeader = req.headers.authorization;
    if(authHeader){
        const token = authHeader.split(' ')[1];
        jwt.verify(token, 'mySecretKey', (err, user)=> {
            if(err) return res.status(403).json('Token is invalid');

            req.user = user;
            next();
        })
    } else {
        return res.status(401).json({error: 'You are not authenticated'})
    }
}

let refreshTokens = [];

app.post('/api/refresh', (req, res)=> {
    const refreshToken = req.body.token;
    if(!refreshToken) return res.status(401).json({error: 'You are unauthenticated'});
    if(!refreshTokens.includes(refreshToken)) return res.status(403).json({error: 'Refresh token not valid'});
    
    jwt.verify(refreshToken, 'myRefreshSecretKey', (err, user)=>{
        err && console.log(err);
        
        refreshTokens = refreshTokens.filter(token => token !== refreshToken);
        
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);

        refreshTokens.push(newRefreshToken);

        return res.status(200).json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken
        })
    })
})

app.post('/api/login', (req, res)=> {
    const { username, password } = req.body;

    // const schema  = {
    //     username: Joi.string().required(),
    //     password: Joi.string().min(6).required()
    // }
    // const result = Joi.Validate(req.body, schema);
    // console.log(result);

    const user = users.find(u => u.username === username && u.password === password);
    if(!user) return res.status(400).json({error: 'Invalid login credentials'})

    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);

    return res.status(200).json({
        userId: user.id,
        username: user.username,
        isAdmin: user.isAdmin,
        accessToken,
        refreshToken
    })

});

app.delete('/api/user/:userId', verify, (req, res)=> {
    if(req.user.userId === parseInt(req.params.userId) || req.user.isAdmin){
        refreshTokens = refreshTokens.filter(token => token !== req.user.refreshToken);
        return res.status(200).json({message: 'User has been deleted successfully'});
    } else {
        return res.status(403).json({error: 'You are not authourized'});
    }
})

app.post('/api/logout', verify, (req, res)=> {
    const refreshToken = req.body.token;
    refreshTokens = refreshTokens.filter(token => token !== refreshToken);
    return res.status(200).json({message: 'Logout successfully'})
})

app.listen(5000, ()=> console.log('serving is running'));