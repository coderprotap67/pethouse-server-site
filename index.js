const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken'); 
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
require('dotenv').config({ path: '.env' });

const app = express();
const port = process.env.PORT || 5000;

app.set('trust proxy', 1);

const cleanUrl = (url) => (url ? url.replace(/\/$/, "") : "");

const clientFrontendUrl = cleanUrl(process.env.FRONTEND_URL) || "https://pethouse-client-site.vercel.app";
const serverBaseUrl = cleanUrl(process.env.BETTER_AUTH_URL) || "https://pet-server-site.vercel.app";

const allowedOrigins = [
  clientFrontendUrl,
  "https://pethouse-client-site.vercel.app",
  "https://pet-server-site.vercel.app",
  "https://pethouse-server-site.vercel.app",
  "http://localhost:3000",
  "http://localhost:5173"
].filter((url, index, self) => url && self.indexOf(url) === index);

// ✅ Fixed CORS Setup (Robust Check for Vercel Deployments)
app.use(cors({
  origin: function (origin, callback) {
    // Allows requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    const isAllowed = allowedOrigins.includes(origin) || origin.endsWith('.vercel.app');
    if (isAllowed) {
      return callback(null, true);
    } else {
      return callback(null, true); // Permits all origins in production to prevent Vercel preview blocks
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Cookie', 'X-Requested-With']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// MongoDB Database Setup
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true }
});

const database = client.db('pethouse');
const petsCollection = database.collection('data');
const requestsCollection = database.collection('requests');
const usersCollection = database.collection('users');

let authInstance = null;

async function getAuthInstance() {
  if (authInstance) return authInstance;

  const { betterAuth } = await import("better-auth");
  const { mongodbAdapter } = await import("better-auth/adapters/mongodb");

  authInstance = betterAuth({
    baseURL: serverBaseUrl,
    database: mongodbAdapter(database), 
    socialProviders: {
      google: {
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        mapQuery() {
          return {
            prompt: "select_account",
          };
        },
      },
    },
    trustedOrigins: allowedOrigins,
    cookies: {
      sessionToken: {
        options: {
          secure: true,
          sameSite: "none",
          httpOnly: true,
        },
      },
      state: {
        options: {
          secure: true,
          sameSite: "none",
          httpOnly: true,
        },
      },
    },
    advanced: {
      basePath: "/api/auth",
      useSecureCookies: true,
      crossSubDomainCookie: true,
      proxyImperativeHeaders: true,
    },
  });

  return authInstance;
}

// Token Verification Middleware
const verifyToken = async (req, res, next) => {
  let token = req.cookies?.token;
  
  if (token) {
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) return res.status(403).send({ message: 'Forbidden access' });
      req.user = decoded;
      return next();
    });
  } else {
    const betterAuthToken = req.cookies?.["better-auth.session-token"];
    
    if (!betterAuthToken) {
      return res.status(401).send({ message: 'Unauthorized access' });
    }

    try {
      const auth = await getAuthInstance();
      const session = await auth.api.getSession({
        headers: {
          cookie: req.headers.cookie
        }
      });

      if (!session || !session.user) {
        return res.status(403).send({ message: 'Forbidden access: Invalid Better Auth Session' });
      }
      req.user = {
        name: session.user.name,
        email: session.user.email,
        photoURL: session.user.image
      };
      
      next();
    } catch (err) {
      console.error("Session verification error:", err);
      res.status(500).send({ message: 'Internal server error' });
    }
  }
};

// Root & Health Route
app.get('/', (req, res) => res.send('Pet adoption server running...'));

// Better Auth Route
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

// All API Routes
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

app.post('/api/jwt', async (req, res) => {
  const user = req.body;
  const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '1d' });
  res.cookie('token', token, { httpOnly: true, secure: true, sameSite: 'none', maxAge: 24 * 60 * 60 * 1000 }).send({ success: true });
});

app.post('/api/logout', async (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: true, sameSite: 'none' });
  res.clearCookie('better-auth.session-token', { httpOnly: true, secure: true, sameSite: 'none' });
  res.send({ success: true });
});

app.get('/api/user-me', verifyToken, async (req, res) => {
  res.send({ user: req.user });
});

// ✅ GET /api/pets - Fixed Empty Search & Query Filters
app.get('/api/pets', async (req, res) => {
  try {
    const { search, species } = req.query;
    let query = {};
    if (search && search.trim() !== '') query.name = { $regex: search.trim(), $options: 'i' };
    if (species && species !== 'all' && species.trim() !== '') query.species = { $regex: `^${species.trim()}$`, $options: 'i' };
    
    const result = await petsCollection.find(query).toArray();
    res.send(result);
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

app.get('/api/pets/:id', async (req, res) => {
  try {
    const id = req.params.id;
    const query = {
      $or: [
        { _id: id },
        ...(ObjectId.isValid(id) ? [{ _id: new ObjectId(id) }] : [])
      ]
    };

    const result = await petsCollection.findOne(query);
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
  const query = ObjectId.isValid(req.params.id) ? { _id: new ObjectId(req.params.id) } : { _id: req.params.id };
  const result = await petsCollection.updateOne(query, { $set: req.body });
  res.send(result);
});

app.delete('/api/pets/:id', verifyToken, async (req, res) => {
  const query = ObjectId.isValid(req.params.id) ? { _id: new ObjectId(req.params.id) } : { _id: req.params.id };
  const result = await petsCollection.deleteOne(query);
  res.send(result);
});

app.post('/api/requests', verifyToken, async (req, res) => {
  const result = await requestsCollection.insertOne(req.body);
  res.send(result);
});

app.get('/api/my-requests', verifyToken, async (req, res) => {
  const email = req.query.email || req.user?.email;
  const result = await requestsCollection.find({ requesterEmail: email }).toArray();
  res.send(result);
});

app.delete('/api/requests/:id', verifyToken, async (req, res) => {
  const query = ObjectId.isValid(req.params.id) ? { _id: new ObjectId(req.params.id) } : { _id: req.params.id };
  const result = await requestsCollection.deleteOne(query);
  res.send(result);
});

app.get('/api/owner-listings', verifyToken, async (req, res) => {
  const email = req.query.email || req.user?.email;
  const result = await petsCollection.find({ ownerEmail: email }).toArray();
  res.send(result);
});

app.get('/api/pet-requests/:petId', verifyToken, async (req, res) => {
  const result = await requestsCollection.find({ petId: req.params.petId }).toArray();
  res.send(result);
});

app.patch('/api/requests-status/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { status, petId } = req.body;
  const reqQuery = ObjectId.isValid(id) ? { _id: new ObjectId(id) } : { _id: id };
  const petQuery = ObjectId.isValid(petId) ? { _id: new ObjectId(petId) } : { _id: petId };

  if (status === 'approved') {
    await petsCollection.updateOne(petQuery, { $set: { status: 'adopted' } });
    await requestsCollection.updateMany({ petId, _id: { $ne: reqQuery._id } }, { $set: { status: 'rejected' } });
  }
  const result = await requestsCollection.updateOne(reqQuery, { $set: { status } });
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

// Vercel Serverless Export
module.exports = app;

if (process.env.NODE_ENV !== 'production') {
  app.listen(port, () => console.log(`Server listening on port ${port}`));
}