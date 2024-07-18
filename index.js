const express = require('express');
const app = express();
require('dotenv').config();
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const port = 3000;

//Middlewares
app.use(express.json());
app.use(cors());

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

    //Setup User
    app.post('/register', async (req, res) => {
      const user = req.body;
      const existingUser = await usersCollections.findOne({ email: user.email });
      if (existingUser) {
        return res.send({ message: 'Email already exists' }).status(409);
      }
      const hash = await bcrypt.hash(user.pin, 10);
      user.pin = hash;
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
          res.send({ user: true });
          return;
        } else {
          res.send({ message: 'Invalid Credintial' }).status(401);
          return;
        }
      }
      console.log(userInfo);
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
