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


const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    accountNumber: { type: String, unique: true, required: true }, // ✅ New field for account number
    accountType: { type: String, enum: ['savings', 'current'], required: true },
    cifNumber: { type: String, unique: true, required: true },
    branchCode: { type: String, required: true },
    country: { type: String, required: true },
    email: { type: String, unique: true, required: true }, 
    mobileNumber: { type: String, required: true },
    username: { type: String, unique: true, required: true },
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
        const { name, accountNumber, accountType, cifNumber, branchCode, country, email, mobileNumber, username, password } = req.body;

        // Check if the account number already exists
        const existingAccount = await User.findOne({ accountNumber });
        if (existingAccount) {
            return res.status(400).json({ error: 'Account number already in use' });
        }

        // Check if email, username, or CIF number already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ error: 'Email already registered' });

        const existingUsername = await User.findOne({ username });
        if (existingUsername) return res.status(400).json({ error: 'Username already taken' });

        const existingCif = await User.findOne({ cifNumber });
        if (existingCif) return res.status(400).json({ error: 'CIF number already registered' });

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save new user
        const user = new User({
            name, 
            accountNumber,  // ✅ Store user-provided account number
            accountType, 
            cifNumber, 
            branchCode, 
            country, 
            email, 
            mobileNumber, 
            username, 
            password: hashedPassword
        });

        await user.save();

        res.status(201).json({ message: 'User registered successfully', accountNumber });
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
            name: user.name,
            username: user.username,
            accountNumber: user.accountNumber || "N/A", // ✅ Ensure it returns even if missing
            accountType: user.accountType,
            cifNumber: user.cifNumber,
            mobileNumber: user.mobileNumber
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
        const { amount, ...extraFields } = req.body;

        // Check if only 'amount' is provided
        if (!amount || Object.keys(extraFields).length > 0) {
            return res.status(400).json({ error: 'Only amount is accepted' });
        }

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
        const { amount, ...extraFields } = req.body;

        // Check if only 'amount' is provided
        if (!amount || Object.keys(extraFields).length > 0) {
            return res.status(400).json({ error: 'Only amount is accepted' });
        }

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
        console.log("🟢 Received Transfer Request");
        console.log("📩 Request Body:", req.body);

        const { accountNumber: recipientAccount, amount } = req.body;

        if (!recipientAccount || typeof recipientAccount !== 'string' || !amount || amount <= 0) {
            console.log("❌ Invalid recipient account number or amount");
            return res.status(400).json({ error: 'Invalid recipient account number or amount' });
        }

        const formattedAccount = String(recipientAccount).trim();

        console.log("🔍 Fetching sender details...");
        const sender = await User.findById(req.userId);
        if (!sender) {
            console.log("❌ Sender not found!");
            return res.status(404).json({ error: 'Sender not found' });
        }

        if (sender.accountNumber === formattedAccount) {
            console.log("❌ Sender is trying to transfer to their own account.");
            return res.status(400).json({ error: 'Cannot transfer to your own account' });
        }

        console.log("🔍 Fetching recipient details...");
        const recipient = await User.findOne({ accountNumber: formattedAccount });
        if (!recipient) {
            console.log("❌ Recipient not found!");
            return res.status(404).json({ error: 'Recipient not found' });
        }

        console.log("💰 Checking sender balance:", sender.balance);
        if (sender.balance < amount) {
            console.log("❌ Insufficient funds! Sender balance:", sender.balance, "Transfer amount:", amount);
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        console.log("💳 Updating balances...");
        sender.balance -= amount;
        recipient.balance += amount;

        await sender.save();
        await recipient.save();
        console.log(`✅ Balances updated! Sender: ${sender.balance}, Recipient: ${recipient.balance}`);

        console.log("📜 Recording transaction...");
        await Transaction.create([
            { userId: sender._id, type: 'transfer', amount, date: new Date() },
            { userId: recipient._id, type: 'deposit', amount, date: new Date() } // ✅ Fixed type
        ]);

        res.json({ message: 'Transfer successful', senderBalance: sender.balance });
    } catch (error) {
        console.error("❌ Transfer error:", error.message);
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
