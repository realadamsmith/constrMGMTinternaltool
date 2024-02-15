import express from 'express';
import mysql from 'mysql';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';

import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(bodyParser.json());
import cors from 'cors';
app.use(cors());
// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME 

});

db.connect((err) => {
    if (err) throw err;
    console.log('Connected to database');
    db.query('SELECT 1', (err, results) => {
        if (err) {
            console.error('Error executing test query:', err);
        } else {
            console.log('Test query successful:', results);
        }
    });
});

// Middleware to verify token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};
app.get('/test', (req, res) => {
    console.log("Got bro")
    res.json({ message: 'This is a test response from your backend' });
  });
// register users 
app.post('/register', async (req, res) => {
    console.log("recieved")
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    // Check if the user already exists
    const userExistsQuery = `SELECT * FROM users WHERE username = ?`;
    db.query(userExistsQuery, [username], async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An error occurred' });
        }
        if (result.length > 0) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash the password
        try {
            const hashedPassword = await bcrypt.hash(password, 10);

            // Insert the new user into the database
            const insertQuery = `INSERT INTO users (username, password) VALUES (?, ?)`;
            db.query(insertQuery, [username, hashedPassword], (err, result) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ error: 'An error occurred' });
                }
                res.status(201).json({ message: 'User created successfully' });
            });
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: 'Could not hash the password' });
        }
    });
});

// User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }
    const userQuery = `SELECT * FROM users WHERE username = ?`;
    db.query(userQuery, [username], async (err, result) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'An error occurred' });
        }
        if (result.length > 0) {
            const user = result[0];
            if (await bcrypt.compare(password, user.password)) {
                const tokenPayload = { id: user.id, username: user.username };
                const accessToken = jwt.sign(tokenPayload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '1h' }); // 1 hour expiration
                res.json({ accessToken });
            } else {
                res.status(401).json({ error: 'Invalid username or password' });
            }
        } else {
            res.status(401).json({ error: 'Invalid username or password' });
        }
    });
});


// CRUD Operations for Projects, Tasks, and Users below
// (Use authenticateToken middleware for protected routes)

// PROJECTS PROJECTS PROJECTS PROJECTS PROJECTS PROJECTS PROJECTS 

// Get all projects
app.get('/projects', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM projects';
    db.query(sql, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

// Get a single project by ID
app.get('/projects/:id', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM projects WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.json(result[0]);
    });
});

// Create a new project
app.post('/projects', authenticateToken, (req, res) => {
    const sql = 'INSERT INTO projects SET ?';
    db.query(sql, req.body, (err, result) => {
        if (err) throw err;
        res.send('Project created');
    });
});

// Update a project
app.put('/projects/:id', authenticateToken, (req, res) => {
    const sql = 'UPDATE projects SET ? WHERE id = ?';
    db.query(sql, [req.body, req.params.id], (err, result) => {
        if (err) throw err;
        res.send('Project updated');
    });
});

// Delete a project
app.delete('/projects/:id', authenticateToken, (req, res) => {
    const sql = 'DELETE FROM projects WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.send('Project deleted');
    });
});


// USERS USERS USERS USERS USERS USERS USERS USERS USERS
// Get all users
app.get('/users', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM users';
    db.query(sql, (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

// Get a single user by ID
app.get('/users/:id', authenticateToken, (req, res) => {
    const sql = 'SELECT * FROM users WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.json(result[0]);
    });
});

// Create a new user
app.post('/users', authenticateToken, (req, res) => {
    const newUser = {...req.body};
    // Ensure password is hashed before storing
    bcrypt.hash(newUser.password, 10, (err, hash) => {
        if (err) throw err;
        newUser.password = hash;
        const sql = 'INSERT INTO users SET ?';
        db.query(sql, newUser, (err, result) => {
            if (err) throw err;
            res.send('User created');
        });
    });
});

// Update a user
app.put('/users/:id', authenticateToken, (req, res) => {
    // Ensure you handle password hashing if password is being updated
    const sql = 'UPDATE users SET ? WHERE id = ?';
    db.query(sql, [req.body, req.params.id], (err, result) => {
        if (err) throw err;
        res.send('User updated');
    });
});

// Delete a user
app.delete('/users/:id', authenticateToken, (req, res) => {
    const sql = 'DELETE FROM users WHERE id = ?';
    db.query(sql, [req.params.id], (err, result) => {
        if (err) throw err;
        res.send('User deleted');
    });
});

//Assign Users to a Project:
app.post('/projects/:projectId/users', authenticateToken, (req, res) => {
    const projectId = req.params.projectId;
    const userId = req.body.userId;
    const sql = 'INSERT INTO project_users (projectId, userId) VALUES (?, ?)';
    db.query(sql, [projectId, userId], (err, result) => {
        if (err) throw err;
        res.send('User assigned to project');
    });
});

//Retrieve All Tasks for a Project:
app.get('/projects/:projectId/tasks', authenticateToken, (req, res) => {
    const projectId = req.params.projectId;
    const sql = 'SELECT * FROM tasks WHERE projectId = ?';
    db.query(sql, [projectId], (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

//Add Cost Record to a Project:
app.post('/projects/:projectId/costs', authenticateToken, (req, res) => {
    const projectId = req.params.projectId;
    const { cost, description } = req.body;
    const sql = 'INSERT INTO project_costs (projectId, cost, description) VALUES (?, ?, ?)';
    db.query(sql, [projectId, cost, description], (err, result) => {
        if (err) throw err;
        res.send('Cost record added to project');
    });
});

// Get All Cost Records for a Project:
app.get('/projects/:projectId/costs', authenticateToken, (req, res) => {
    const projectId = req.params.projectId;
    const sql = 'SELECT * FROM project_costs WHERE projectId = ?';
    db.query(sql, [projectId], (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

//Get Project Progress:
app.get('/projects/:projectId/progress', authenticateToken, (req, res) => {
    const projectId = req.params.projectId;
    // A query that calculates the project progress based on tasks or other metrics
    const sql = 'SELECT ... FROM ... WHERE projectId = ?';
    db.query(sql, [projectId], (err, result) => {
        if (err) throw err;
        res.json(result);
    });
});

//Update Task Status:
app.put('/tasks/:taskId/status', authenticateToken, (req, res) => {
    const taskId = req.params.taskId;
    const status = req.body.status; // New status of the task
    const sql = 'UPDATE tasks SET status = ? WHERE id = ?';
    db.query(sql, [status, taskId], (err, result) => {
        if (err) throw err;
        res.send('Task status updated');
    });
});


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});