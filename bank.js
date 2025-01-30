// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

// Initialize Express app
const app = express();
app.use(express.json());
app.use(cors());

// MongoDB connection string
const dbURI = 'mongodb+srv://User1:use123@cluster0.rpeqo.mongodb.net/banking?retryWrites=true&w=majority&appName=Cluster0';

// Connect to MongoDB
mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log(' MongoDB connected'))
    .catch(err => {
        console.error('MongoDB connection error:', err);
        process.exit(1);
    });

// JWT Secret (hardcoded)
const JWT_SECRET = 'mySuperSecretKey123!'; // Change this to your secret key

// User Schema
// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    accountType: { type: String, enum: ['savings', 'current'], required: true }, // New field for account type
    cifNumber: { type: String, unique: true, required: true }, // New field for CIF number
    branchCode: { type: String, required: true }, // New field for branch code
    country: { type: String, required: true }, // New field for country
    email: { type: String, unique: true, required: true }, 
    mobileNumber: { type: String, required: true }, // New field for mobile number
    username: { type: String, unique: true, required: true }, // New field for username
    password: { type: String, required: true }, 
    balance: { type: Number, default: 0 },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }]
});
const User = mongoose.model('User', userSchema);

// Transaction Schema
const transactionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    type: { type: String, enum: ['deposit', 'withdraw', 'transfer'], required: true },
    amount: { type: Number, required: true },
    date: { type: Date, default: Date.now }
});
const Transaction = mongoose.model('Transaction', transactionSchema);

// Signup Route
app.post('/signup', async (req, res) => {
    try {
        const { name, accountType, cifNumber, branchCode, country, email, mobileNumber, username, password } = req.body;

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Check if username already exists
        const existingUsername = await User.findOne({ username });
        if (existingUsername) {
            return res.status(400).json({ error: 'Username already taken' });
        }

        // Check if CIF number already exists
        const existingCif = await User.findOne({ cifNumber });
        if (existingCif) {
            return res.status(400).json({ error: 'CIF number already registered' });
        }

        // Hash the password and save new user
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ name, accountType, cifNumber, branchCode, country, email, mobileNumber, username, password: hashedPassword });
        await user.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Check if user exists using the username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Compare hashed passwords
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate JWT token
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

        // Return user information along with the token
        const userInfo = {
            username: user.username,
            accountNumber: user.accountNumber, // Assuming the account number field exists in the User schema
            accountType: user.accountType,     // Assuming the account type field exists in the User schema
            cifNumber: user.cifNumber,         // Assuming the CIF number field exists in the User schema
            mobileNumber: user.mobileNumber    // Assuming the mobile number field exists in the User schema
        };

        res.json({
            message: 'Login successful',
            token,
            user: userInfo
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login error' });
    }
});


// Middleware for authentication
const authenticate = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) {
        console.log(' No token provided');
        return res.status(401).json({ error: 'Access denied' });
    }

    try {
        const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);  // Use `split(' ')[1]` to get the token part after 'Bearer'
        console.log(' Token decoded:', decoded);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.error('Invalid token error:', error);
        return res.status(400).json({ error: 'Invalid token' });
    }
};


// View Balance Route
app.get('/balance', authenticate, async (req, res) => {
    try {
        const user = await User.findById(req.userId);
        res.json({ balance: user.balance });
    } catch (error) {
        res.status(500).json({ error: 'Error fetching balance' });
    }
});

// Deposit Route
app.post('/deposit', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.userId);
        user.balance += amount;
        await user.save();
        await Transaction.create({ userId: user._id, type: 'deposit', amount });
        res.json({ message: 'Deposit successful', balance: user.balance });
    } catch (error) {
        res.status(500).json({ error: 'Deposit error' });
    }
});

// Withdraw Route
app.post('/withdraw', authenticate, async (req, res) => {
    try {
        const { amount } = req.body;
        const user = await User.findById(req.userId);
        if (user.balance < amount) return res.status(400).json({ error: 'Insufficient funds' });
        user.balance -= amount;
        await user.save();
        await Transaction.create({ userId: user._id, type: 'withdraw', amount });
        res.json({ message: 'Withdrawal successful', balance: user.balance });
    } catch (error) {
        res.status(500).json({ error: 'Withdrawal error' });
    }
});

app.post('/transfer', authenticate, async (req, res) => {
    try {
        console.log("Received Transfer Request");
        console.log(" Request Body:", req.body);

        const { email: recipientEmail, amount } = req.body;

        if (!recipientEmail || typeof recipientEmail !== 'string' || !amount || amount <= 0) {
            console.log("❌ Invalid recipient email or amount");
            return res.status(400).json({ error: 'Invalid recipient email or amount' });
        }

        const formattedEmail = recipientEmail.trim().toLowerCase();

        // Find sender
        const sender = await User.findById(req.userId);
        if (!sender) {
            return res.status(404).json({ error: 'Sender not found' });
        }

        // Find recipient
        const recipient = await User.findOne({ email: formattedEmail });
        if (!recipient) {
            return res.status(404).json({ error: 'Recipient not found' });
        }

        // Check if sender has enough balance
        if (sender.balance < amount) {
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        // Update balances
        sender.balance -= amount;
        recipient.balance += amount;

        await sender.save();
        await recipient.save();

        // Record transactions
        await Transaction.create([
            { userId: sender._id, type: 'transfer', amount: amount },
            { userId: recipient._id, type: 'transfer', amount: amount }
        ]);

        res.json({ message: 'Transfer successful', senderBalance: sender.balance });
    } catch (error) {
        console.error("❌ Error during transfer:", error);
        res.status(500).json({ error: "Transfer failed" });
    }
});

// Change Password Route
app.put('/change-password', authenticate, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;

        // Validate input
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: 'Old and new passwords are required' });
        }

        // Find user
        const user = await User.findById(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Compare old password
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Incorrect old password' });
        }

        // Hash new password and update
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();

        res.json({ message: 'Password updated successfully' });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Password update failed' });
    }
});

// Delete User Route
app.delete('/delete-account', authenticate, async (req, res) => {
    try {
        // Find and delete the user
        const user = await User.findByIdAndDelete(req.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete user's transactions
        await Transaction.deleteMany({ userId: req.userId });

        res.json({ message: 'Account deleted successfully' });
    } catch (error) {
        console.error('Account deletion error:', error);
        res.status(500).json({ error: 'Account deletion failed' });
    }
});

// View Transactions Route
app.get('/transactions', authenticate, async (req, res) => {
    try {
        // Fetch transactions related to the user
        const transactions = await Transaction.find({ userId: req.userId });

        if (!transactions || transactions.length === 0) {
            return res.status(404).json({ error: 'No transactions found' });
        }

        // Return the user's transactions
        res.json({ transactions });
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ error: 'Error fetching transactions' });
    }
});


  
// Start server
const PORT = 5003;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
