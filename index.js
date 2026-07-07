const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config({ path: '.env' });

const app = express();
const port = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: [process.env.FRONTEND_URL || 'http://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).send({ message: 'Unauthorized access' });
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: 'Forbidden access' });
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    // image_9ffb4b.png matching Database & Collection
    const database = client.db('pethouse');
    const petsCollection = database.collection('data');
    const requestsCollection = database.collection('requests');

    // Auth APIs
    app.post('/api/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1d' });
      res.cookie('token', token, {
        httpOnly: true,
        secure: true,
        sameSite: 'none'
      }).send({ success: true });
    });

    app.post('/api/logout', async (req, res) => {
      res.clearCookie('token', { maxAge: 0, secure: true, sameSite: 'none' }).send({ success: true });
    });

    // Get Logged-in User Info (Handles Route Reload issues)
    app.get('/api/user-me', verifyToken, async (req, res) => {
      res.send({ user: req.user });
    });

    // Pets - Advanced Search, Filter ($regex, $in)
    app.get('/api/pets', async (req, res) => {
      const { search, species } = req.query;
      let query = {};

      if (search) {
        query.name = { $regex: search, $options: 'i' };
      }
      if (species && species !== 'all') {
        query.species = { $in: [species] };
      }

      const result = await petsCollection.find(query).toArray();
      res.send(result);
    });

    app.get('/api/pets/:id', async (req, res) => {
      const id = req.params.id;
      const result = await petsCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.post('/api/pets', verifyToken, async (req, res) => {
      const newPet = req.body;
      const result = await petsCollection.insertOne(newPet);
      res.send(result);
    });

    app.put('/api/pets/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const filter = { _id: new ObjectId(id) };
      const updatedPet = { $set: req.body };
      const result = await petsCollection.updateOne(filter, updatedPet);
      res.send(result);
    });

    app.delete('/api/pets/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const result = await petsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    // Adoption Requests Handling
    app.post('/api/requests', verifyToken, async (req, res) => {
      const requestData = req.body;
      const result = await requestsCollection.insertOne(requestData);
      res.send(result);
    });

    app.get('/api/my-requests', verifyToken, async (req, res) => {
      const email = req.query.email;
      const result = await requestsCollection.find({ requesterEmail: email }).toArray();
      res.send(result);
    });

    app.delete('/api/requests/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const result = await requestsCollection.deleteOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.get('/api/owner-listings', verifyToken, async (req, res) => {
      const email = req.query.email;
      const result = await petsCollection.find({ ownerEmail: email }).toArray();
      res.send(result);
    });

    app.get('/api/pet-requests/:petId', verifyToken, async (req, res) => {
      const petId = req.params.petId;
      const result = await requestsCollection.find({ petId }).toArray();
      res.send(result);
    });

    app.patch('/api/requests-status/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const { status, petId } = req.body;

      if (status === 'approved') {
        // Mark the pet as adopted and reject all other requests for this pet
        await petsCollection.updateOne({ _id: new ObjectId(petId) }, { $set: { status: 'adopted' } });
        await requestsCollection.updateMany({ petId, _id: { $ne: new ObjectId(id) } }, { $set: { status: 'rejected' } });
      }

      const result = await requestsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
      res.send(result);
    });

    console.log("Successfully connected to MongoDB!");
  } catch (error) {
    console.error(error);
  }
}
run().catch(console.dir);

app.get('/', (req, res) => res.send('Pet adoption server running...'));
app.listen(port, () => console.log(`Server listening on port ${port}`));