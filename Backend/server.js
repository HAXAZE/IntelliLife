

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('Error connecting to MongoDB:', err));

// Define MongoDB schema and model for users
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Define MongoDB schema and model for todos
const todoSchema = new mongoose.Schema({
    description: String,
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
});

const Todo = mongoose.model('Todo', todoSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Forbidden' });
        req.user = user;
        next();
    });
};

app.use(express.json());

// Signup route
app.post('/api/signup', async (req, res) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        // Create and send JWT token
        const token = jwt.sign({ username: newUser.username }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Login route
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create and send JWT token
        const token = jwt.sign({ username: user.username }, process.env.JWT_SECRET);
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Todo routes
app.get('/api/todos', verifyToken, async (req, res) => {
    try {
        const todos = await Todo.find({ userId: req.user._id });
        res.json(todos);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/todos', verifyToken, async (req, res) => {
    try {
        const { description } = req.body;
        const newTodo = new Todo({ description, userId: req.user._id });
        await newTodo.save();
        res.json(newTodo);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// Get user information route
app.get('/api/user-info', verifyToken, async (req, res) => {
    try {
        const user = await User.findOne({ username: req.user.username }, { password: 0 }); // Exclude password from response
        res.json(user);
    } catch (error) {
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
