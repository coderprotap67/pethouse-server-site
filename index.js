const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken'); 
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config({ path: '.env' });

const app = express();
const port = process.env.PORT || 5000;

app.set('trust proxy', 1);
app.use(cors({
  origin: [process.env.FRONTEND_URL || "https://pet-client-site.vercel.app"],
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

const verifyToken = (req, res, next) => {
  const token = req.cookies?.token;
  if (!token) return res.status(401).send({ message: 'Unauthorized access' });
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: 'Forbidden access' });
    req.user = decoded;
    next();
  });
};

let authInstance;

const getAuthInstance = async () => {
  if (!authInstance) {
    const { betterAuth } = await import("better-auth");
    const { mongodbAdapter } = await import("better-auth/adapters/mongodb");
    
    if (!client.topology || !client.topology.isConnected()) {
      await client.connect();
    }

    authInstance = betterAuth({
      database: mongodbAdapter(client.db('pethouse')), 
      socialProviders: {
        google: {
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        },
      },
      trustedOrigins: [
        "https://pet-client-site.vercel.app", 
        "http://localhost:3000"
      ],
      cookies: {
        sessionToken: {
          options: {
            secure: true,
            sameSite: "none",
          }
        }
      },
      advanced: {
        basePath: "/api/auth",
        disableCSRFCheck: true 
      }
    });
  }
  return authInstance;
};
app.all(/^\/api\/auth\/.*/, async (req, res) => {
  try {
    const { toNodeHandler } = await import("better-auth/node");
    const auth = await getAuthInstance();
    return toNodeHandler(auth)(req, res);
  } catch (err) {
    console.error("Better Auth error: ", err);
    res.status(500).send({ error: err.message });
  }
});
async function run() {
  try {
    const database = client.db('pethouse');
    const petsCollection = database.collection('data');
    const requestsCollection = database.collection('requests');
    const usersCollection = database.collection('users'); 

    app.post('/api/register', async (req, res) => {
      try {
        const { name, email, password } = req.body;
        if (!email || !password) return res.status(400).send({ success: false, message: 'Email and password are required!' });
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) return res.status(400).send({ success: false, message: 'User already exists!' });
        const newUser = { name, email, password };
        const result = await usersCollection.insertOne(newUser);
        res.send({ success: true, message: 'User registered successfully!', result });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });
    
    app.post('/api/login', async (req, res) => {
      try {
        const { email, password } = req.body;   
        const user = await usersCollection.findOne({ email });
        if (!user || user.password?.trim() !== password?.trim()) {
          return res.status(401).send({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ name: user.name, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 })
          .send({ success: true, user: { name: user.name, email: user.email } });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.post('/api/google-login', async (req, res) => {
      try {
        const { name, email, photoURL } = req.body;
        if (!email) return res.status(400).send({ success: false, message: 'Email is required from Google' });
        let user = await usersCollection.findOne({ email });
        if (!user) {
          const newUser = { name, email, photoURL: photoURL || "https://placedog.net/200", role: "user", authProvider: 'google' };
          await usersCollection.insertOne(newUser);
          user = newUser;
        }
        const token = jwt.sign({ name: user.name, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 })
          .send({ success: true, user: { name: user.name, email: user.email } });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    app.post('/api/jwt', async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1d' });
      res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }).send({ success: true });
    });

    app.post('/api/logout', async (req, res) => {
      res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' }).send({ success: true });
    });

    app.get('/api/user-me', verifyToken, async (req, res) => {
      res.send({ user: req.user });
    });

    app.get('/api/pets', async (req, res) => {
      try {
        const { search, species } = req.query;
        let query = {};
        if (search) query.name = { $regex: search, $options: 'i' };
        if (species && species !== 'all') query.species = { $regex: `^${species}$`, $options: 'i' };
        const result = await petsCollection.find(query).toArray();
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.get('/api/pets/:id', async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) return res.status(400).send({ message: 'Invalid ID format' });
        const result = await petsCollection.findOne({ _id: new ObjectId(id) });
        if (!result) return res.status(404).send({ message: 'Pet not found' });
        res.send(result);
      } catch (error) {
        res.status(500).send({ message: error.message });
      }
    });

    app.post('/api/pets', verifyToken, async (req, res) => {
      const result = await petsCollection.insertOne(req.body);
      res.send(result);
    });

    app.put('/api/pets/:id', verifyToken, async (req, res) => {
      const result = await petsCollection.updateOne({ _id: new ObjectId(req.params.id) }, { $set: req.body });
      res.send(result);
    });

    app.delete('/api/pets/:id', verifyToken, async (req, res) => {
      const result = await petsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.post('/api/requests', verifyToken, async (req, res) => {
      const result = await requestsCollection.insertOne(req.body);
      res.send(result);
    });

    app.get('/api/my-requests', verifyToken, async (req, res) => {
      const result = await requestsCollection.find({ requesterEmail: req.query.email }).toArray();
      res.send(result);
    });

    app.delete('/api/requests/:id', verifyToken, async (req, res) => {
      const result = await requestsCollection.deleteOne({ _id: new ObjectId(req.params.id) });
      res.send(result);
    });

    app.get('/api/owner-listings', verifyToken, async (req, res) => {
      const result = await petsCollection.find({ ownerEmail: req.query.email }).toArray();
      res.send(result);
    });

    app.get('/api/pet-requests/:petId', verifyToken, async (req, res) => {
      const result = await requestsCollection.find({ petId: req.params.petId }).toArray();
      res.send(result);
    });

    app.patch('/api/requests-status/:id', verifyToken, async (req, res) => {
      const id = req.params.id;
      const { status, petId } = req.body;
      if (status === 'approved') {
        await petsCollection.updateOne({ _id: new ObjectId(petId) }, { $set: { status: 'adopted' } });
        await requestsCollection.updateMany({ petId, _id: { $ne: new ObjectId(id) } }, { $set: { status: 'rejected' } });
      }
      const result = await requestsCollection.updateOne({ _id: new ObjectId(id) }, { $set: { status } });
      res.send(result);
    });

    app.put('/api/update-profile', verifyToken, async (req, res) => {
      try {
        const { name, photoURL, currentPassword, newPassword } = req.body;
        const email = req.user.email; 
        const user = await usersCollection.findOne({ email });
        if (!user) return res.status(404).send({ success: false, message: 'User not found' });
        
        let updatedData = { name, photoURL };
        if (currentPassword && newPassword) {
          if (user.authProvider === 'google') return res.status(400).send({ success: false, message: 'Google users cannot change password.' });
          if (user.password?.trim() !== currentPassword?.trim()) return res.status(400).send({ success: false, message: 'Current password is incorrect.' });
          if (newPassword.length < 6) return res.status(400).send({ success: false, message: 'New password must be at least 6 characters.' });
          updatedData.password = newPassword; 
        }
        await usersCollection.updateOne({ email }, { $set: updatedData });
        const updatedUser = await usersCollection.findOne({ email }); 
        res.send({ success: true, user: { name: updatedUser.name, email: updatedUser.email, photoURL: updatedUser.photoURL } });
      } catch (error) {
        res.status(500).send({ success: false, message: error.message });
      }
    });

    console.log("Successfully connected to MongoDB!");
  } catch (error) {
    console.error(error);
  }
}
run().catch(console.dir);

app.get('/', (req, res) => res.send('Pet adoption server running...'));
app.listen(port, () => console.log(`Server listening on port ${port}`));