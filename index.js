const express = require('express');
const cors = require('cors');
const app = express();
const jwt = require('jsonwebtoken')
require('dotenv').config()
const bcrypt = require('bcryptjs')
const port = process.env.PORT || 8000;
const { MongoClient, ServerApiVersion } = require('mongodb');

app.use(cors())
app.use(express.json());


const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.al6znur.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;


// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

// middleware for authentication
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token)
        return res.status(401).send({ message: 'No token given' })
    jwt.verify(token, process.env.JWT_TOKEN, (err, decoded) => {
        if (err) {
            console.log('token verification error', err)
            return res.status(401).send({ message: 'Unauthorized access' })
        }
        req.decoded = decoded;
        next()
    })
}


const userCollection = client.db('cashPulse').collection('users')

// register
app.post('/register', async(req, res)=>{
    const {name, email, mobile, role, pin} = req.body;
    const hashedPin = await bcrypt.hash(pin, 10)
    const result = await userCollection.insertOne({
        name,
        email,
        mobile,
        role,
        pin: hashedPin,
        status: 'pending',
        balance: role === 'Agent' ? 10000 : role === 'New User' ? 40 : 0,
    })
    res.send(result)
})

// login

app.post('/login', async (req, res) => {
    const { identifier, pin } = req.body;
    if (!identifier || !pin) {
        return res.status(400).send({ message: 'Email/Mobile and PIN are required' });
    }
    const user = await userCollection.findOne({
        $or: [{ email: identifier }, { mobile: identifier }],
    });
    if (!user) {
        return res.status(400).send({ message: 'User not found' });
    }
    const isMatch = await bcrypt.compare(pin, user.pin);
    if (!isMatch) {
        return res.status(400).send({ message: 'Invalid Credentials' });
    }
    if (user.status !== 'approved') {
        return res.status(400).send({ message: 'Account is not approved yet' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_TOKEN, { expiresIn: '365d' });
    res.send({ token, user: { name: user.name, email: user.email, mobile: user.mobile, role: user.role } });
});



async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();
        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);



app.get('/', (req, res) => {
    res.send('cash pulse is activated')
})

app.listen(port, () => {
    console.log(`cash pulse is running on port ${port}`)
})