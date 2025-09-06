const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

// @desc Login
// @route POST /auth/login
// @access Public
const login = async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ message: 'Username and password are required' });
    }
    
    try {
        const foundUser = await User.findOne({ username }).exec();
        
        if (!foundUser || !foundUser.active) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        
        const match = await bcrypt.compare(password, foundUser.password);
        
        if (match) {
            const roles = Object.values(foundUser.roles).filter(Boolean);
            
            // Create JWTs
            const accessToken = jwt.sign(
                {
                    "UserInfo": {
                        "username": foundUser.username,
                        "roles": roles
                    }
                },
                process.env.ACCESS_TOKEN_SECRET,
                { expiresIn: '15m' }
            );
            
            const refreshToken = jwt.sign(
                { "username": foundUser.username },
                process.env.REFRESH_TOKEN_SECRET,
                { expiresIn: '7d' }
            );
            
            // Save refresh token with current user
            foundUser.refreshToken = refreshToken;
            await foundUser.save();
            
            // Creates Secure Cookie with refresh token
            res.cookie('jwt', refreshToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'None', 
                maxAge: 7 * 24 * 60 * 60 * 1000 
            });
            
            res.json({ 
                accessToken,
                user: {
                    username: foundUser.username,
                    email: foundUser.email,
                    roles: roles
                }
            });
        } else {
            res.status(401).json({ message: 'Unauthorized' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// @desc Refresh
// @route GET /auth/refresh
// @access Public - because access token has expired
const refresh = async (req, res) => {
    const cookies = req.cookies;
    
    if (!cookies?.jwt) return res.status(401).json({ message: 'Unauthorized' });
    
    const refreshToken = cookies.jwt;
    
    try {
        const foundUser = await User.findOne({ refreshToken }).exec();
        if (!foundUser) return res.status(403).json({ message: 'Forbidden' });
        
        // Evaluate jwt
        jwt.verify(
            refreshToken,
            process.env.REFRESH_TOKEN_SECRET,
            (err, decoded) => {
                if (err || foundUser.username !== decoded.username) {
                    return res.status(403).json({ message: 'Forbidden' });
                }
                
                const roles = Object.values(foundUser.roles);
                const accessToken = jwt.sign(
                    {
                        "UserInfo": {
                            "username": decoded.username,
                            "roles": roles
                        }
                    },
                    process.env.ACCESS_TOKEN_SECRET,
                    { expiresIn: '15m' }
                );
                res.json({ accessToken });
            }
        );
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// @desc Logout
// @route POST /auth/logout
// @access Public - just to clear cookie if exists
const logout = async (req, res) => {
    const cookies = req.cookies;
    if (!cookies?.jwt) return res.sendStatus(204); // No content
    
    const refreshToken = cookies.jwt;
    
    try {
        // Is refreshToken in db?
        const foundUser = await User.findOne({ refreshToken }).exec();
        if (!foundUser) {
            res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
            return res.sendStatus(204);
        }
        
        // Delete refreshToken in db
        foundUser.refreshToken = '';
        await foundUser.save();
        
        res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true });
        res.sendStatus(204);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

// @desc Register
// @route POST /auth/register
// @access Public
const register = async (req, res) => {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({ message: 'All fields are required' });
    }
    
    try {
        // Check for duplicate usernames in the db
        const duplicate = await User.findOne({ 
            $or: [{ username }, { email }] 
        }).lean().exec();
        
        if (duplicate) {
            return res.status(409).json({ message: 'Username or email already exists' });
        }
        
        // Hash password
        const hashedPwd = await bcrypt.hash(password, 10);
        
        const userObject = { 
            username, 
            email,
            password: hashedPwd 
        };
        
        // Create and store new user
        const user = await User.create(userObject);
        
        if (user) {
            res.status(201).json({ 
                message: `New user ${username} created successfully` 
            });
        } else {
            res.status(400).json({ message: 'Invalid user data received' });
        }
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
};

module.exports = {
    login,
    refresh,
    logout,
    register
};