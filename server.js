const env = require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const path = require("path");
const app = express();
app.use(express.json());

// CORS configuration
const whitelist = ['https://dri-ev.vercel.app', 'http://localhost:3000']; // Add your frontend URL to the whitelist
const corsOptions = {
    origin: (origin, callback) => {
        if (whitelist.indexOf(origin) !== -1 || !origin) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ["POST", "GET", "PUT", "DELETE"],  // Allow specific methods
    credentials: true,  // Allow credentials (cookies, authorization headers)
    optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));
app.use(cookieParser());

console.log('MongoDB_URI:', process.env.MONGODB_URI);
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Failed to connect to MongoDB', err));

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const employeeSchema = new mongoose.Schema({
    name: String,
    position: String,
    department: String,
});

const User = mongoose.model('User', userSchema);
const Employee = mongoose.model('Employee', employeeSchema);

// Middleware for verifying token
const authenticateToken = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.sendStatus(403);

    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Routes
app.get('/OK', async (req, res) => {
    res.send('hello');
});

app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).send('User created');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ userId: user._id }, 'secretkey', { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: false }); // Set secure: true in production
        res.status(200).send('Logged in successfully');
    } else {
        res.status(400).send('Invalid credentials');
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token');
    res.send('Logged out successfully');
});

// CRUD Operations for Employees with Authentication
app.get('/employees', authenticateToken, async (req, res) => {
    const employees = await Employee.find();
    res.json(employees);
});

app.post('/employees', authenticateToken, async (req, res) => {
    const newEmployee = new Employee(req.body);
    await newEmployee.save();
    res.status(201).send('Employee added');
});

app.put('/employees/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    await Employee.findByIdAndUpdate(id, req.body);
    res.send('Employee updated');
});

app.delete('/employees/:id', authenticateToken, async (req, res) => {
    const { id } = req.params;
    await Employee.findByIdAndDelete(id);
    res.send('Employee deleted');
});

// Error handling middleware for CORS issues
app.use((err, req, res, next) => {
    if (err) {
        console.error('CORS error:', err);
        res.status(500).send('CORS error occurred');
    } else {
        next();
    }
});

app.listen(5000, () => console.log('Server running on port 5000'));
