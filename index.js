const express = require('express');
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const port = 3000;

//Middlewares
app.use(express.json());
app.use(cors());

//Verfify JWT Token Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization.split(' ')[1];
  if (!token) return res.send({ message: 'Invalid' }).status(400);
  else if (token) {
    jwt.verify(token, process.env.TOKEN, (err, decoded) => {
      if (err) {
        return res.send({ message: 'Unauthorized' }).status(401);
      } else {
        req.user = decoded;
        next();
      }
    });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.mal3t53.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();
    // Send a ping to confirm a successful connection

    const usersCollections = client.db('easyPay').collection('users');

    //Verify Admin Access
    const verifyAdminAccess = async (req, res, next) => {
      const username = req.body.username;
      const secret = req.body.secret;
      //return if username and secret are not there
      if (!username || !secret) {
        return res.send({ message: 'UnAthorized' }).status(401);
      }
      const query = {
        $or: [
          {
            email: username,
          },
          {
            phone: username,
          },
        ],
      };
      const result = await usersCollections.findOne(query);
      if (!result) {
        return res.send({ message: forbidden }).status(401);
      }
      const validPIN = result.pin === secret;
      if (validPIN) {
        if (result.role !== 'admin') {
          return res.send({ message: forbidden }).status(401);
        }
        next();
      }
    };

    //Register User
    app.post('/register', async (req, res) => {
      const user = req.body;
      const query = {
        $or: [{ email: user.email }, { phone: user.phone }],
      };
      const existingUser = await usersCollections.findOne(query);
      if (existingUser) {
        return res.send({ message: 'Email or Phone already exists' }).status(409);
      }
      const hash = await bcrypt.hash(user.pin, 10);
      user.pin = hash;
      // Set New User Status to pending
      user.status = 'pending';
      user.balance = 0;
      const result = await usersCollections.insertOne(user);
      res.send(result);
    });

    //Login User
    app.post('/login', async (req, res) => {
      const userInfo = req.body;
      const isUser =
        (await usersCollections.findOne({ email: userInfo.username })) || (await usersCollections.findOne({ phone: userInfo.username }));
      if (isUser) {
        const validPIN = await bcrypt.compare(userInfo.pin, isUser.pin);
        if (validPIN) {
          //Sent JWT token
          const token = jwt.sign({ username: userInfo.username }, process.env.TOKEN, { expiresIn: '1h' });
          res.send({ user: userInfo.username, secret: isUser.pin, token: token });
          return;
        } else {
          console.log('not found');
          res.send({ message: 'Invalid Credintial' }).status(401);
          return;
        }
      } else {
        res.send({ message: 'Invalid Credintial' }).status(401);
        return;
      }
    });

    //Check if user is authenticated and give role
    app.post('/verify', verifyToken, async (req, res) => {
      const username = req.body.username;
      // Check if user is authenticated and give role
      const query = {
        $or: [
          {
            email: username,
          },
          {
            phone: username,
          },
        ],
      };
      const result = await usersCollections.findOne(query);

      if (!result) {
        return res.send({ isVerified: false }).status(401);
      } else if (result) {
        // Compare passwords to ensure authentication
        const validPIN = result.pin === req.body.secret;
        if (validPIN) {
          res.send({ isVerified: true, role: result.role }).status(200);
        } else {
          return res.send({ isVerified: false }).status(401);
        }
      }
    });

    // Give User Info to Admin
    app.post('/users', verifyToken, verifyAdminAccess, async (req, res) => {
      const query = { role: 'user' };
      const result = await usersCollections.find(query).toArray();
      res.send(result);
    });

    //Give user approve role
    app.patch('/approve', verifyToken, verifyAdminAccess, async (req, res) => {
      const id = req.body.id;
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          status: 'approved',
        },
      };
      const result = await usersCollections.updateOne(query, updateDoc);
      res.send(result);
    });

    await client.db('admin').command({ ping: 1 });
    console.log('Pinged your deployment. You successfully connected to MongoDB!');
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Welcome to the custom API server!');
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}...`);
});
