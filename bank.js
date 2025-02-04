// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const moment = require('moment-timezone');
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
    accountNumber: { type: String, unique: true, required: true },
    accountType: { type: String, enum: ['savings', 'current'], required: true },
    cifNumber: { type: String, unique: true, required: true },
    branchCode: { type: String, required: true },
    country: { type: String, required: true },
    email: { type: String, unique: true, required: true }, 
    mobileNumber: { type: String, required: true },
    username: { type: String, unique: true, required: true },
    password: { type: String, required: true }, 
    dob: { type: String, required: true },
    balance: { type: Number, default: 0 },
    transactions: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Transaction' }],
    role: { type: String, enum: ['admin', 'user'], default: 'user' },
    isActivated: { type: Boolean, default: false },
    isLocked: { type: Boolean, default: false }
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

app.post('/signup', async (req, res) => {
    try {
        console.log('Received data:', JSON.stringify(req.body, null, 2)); // Debugging log

        const { 
            name, accountNumber, accountType, cifNumber, 
            branchCode, country, email, mobileNumber, 
            username, password, dob  
        } = req.body;

        // Improved validation logic
        if ([name, accountNumber, accountType, cifNumber, branchCode, country, email, mobileNumber, username, password, dob]
            .some(value => value === undefined || value === null || (typeof value === 'string' && value.trim() === ""))) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({ 
            name, 
            accountNumber, 
            accountType, 
            cifNumber, 
            branchCode, 
            country, 
            email, 
            mobileNumber, 
            username, 
            password: hashedPassword, 
            dob 
        });

        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ error: error.message });
    }
});




// Login Route (Fixed)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username }).select('+password');  // Ensure password is retrieved

        if (!user) return res.status(401).json({ error: 'Invalid credentials' });
        if (!user.isActivated) return res.status(403).json({ error: 'Account not activated' });
        if (user.isLocked) return res.status(403).json({ error: 'Account is locked' });

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) return res.status(401).json({ error: 'Invalid credentials' });

        const token = jwt.sign({ id: user._id.toString() }, JWT_SECRET, { expiresIn: "1h" });


        res.json({ 
            message: 'Login successful', 
            token, 
            user: { 
                name: user.name, 
                username: user.username, 
                accountNumber: user.accountNumber,  // ✅ Include account number
                accountType: user.accountType,      // ✅ Include account type
                balance: user.balance,              // ✅ Include balance
                mobileNumber: user.mobileNumber     // ✅ Include mobile number
            } 
        });
    } catch (error) {
        console.error('❌ Login Error:', error);  
        res.status(500).json({ error: 'Login error' });
    }
});


const authenticate = (req, res, next) => {
    const authHeader = req.header("Authorization");

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Access denied. No token provided." });
    }

    const token = authHeader.split(" ")[1];

    try {
        // Decode token using JWT_SECRET
        const decoded = jwt.verify(token, JWT_SECRET);

        // Ensure decoded token has id field
        if (!decoded || !decoded.id) {
            return res.status(401).json({ error: "Invalid token: Missing user data." });
        }

        // Attach user ID to the request object
        req.user = { id: decoded.id };

        console.log("✅ Authenticated User ID:", req.user.id);

        next();
    } catch (error) {
        console.error("❌ Invalid token:", error.message);
        return res.status(403).json({ error: "Invalid token" });
    }
};



module.exports = authenticate;


// Middleware to check if the user is an admin
const checkAdmin = (req, res, next) => {
    if (req.userRole !== 'admin') {
        return res.status(403).json({ error: 'Access denied. Admins only.' });
    }
    next();
};

app.get('/admin/users', authenticate, checkAdmin, async (req, res) => {
    try {
        const users = await User.find({}, 'username role email _id'); // Include role
        res.json({ users });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

app.get('/balance', authenticate, async (req, res) => {
    try {
        console.log("Decoded User from Token:", req.user); // Debugging

        if (!req.user || !req.user.id) {
            return res.status(401).json({ error: "Unauthorized: Invalid user data in token" });
        }

        const user = await User.findById(req.user.id); // Use req.user.id instead of req.userId

        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        res.json({
            name: user.name,
            accountHolderName: user.name,
            accountNumber: user.accountNumber,
            accountType: user.accountType,
            cifNumber: user.cifNumber,
            branchCode: user.branchCode,
            country: user.country,
            mobileNumber: user.mobileNumber,
            balance: user.balance
        });

    } catch (error) {
        console.error("Error fetching balance:", error);
        res.status(500).json({ error: "Internal Server Error" });
    }
});


app.post('/deposit', authenticate, async (req, res) => {
    try {
        const { amount, ...extraFields } = req.body;

        if (!amount || isNaN(amount) || amount <= 0 || Object.keys(extraFields).length > 0) {
            return res.status(400).json({ error: 'Only a valid amount is accepted' });
        }

        console.log("🔍 User ID from req:", req.user.id); // Debugging

        if (!req.user.id || !mongoose.Types.ObjectId.isValid(req.user.id)) {
            return res.status(400).json({ error: "Invalid or missing user ID" });
        }

        const user = await User.findById(req.user.id);
        if (!user) return res.status(404).json({ error: "User not found" });

        user.balance += amount;
        await user.save();

        const istTime = moment().tz("Asia/Kolkata").format();
        await Transaction.create({ userId: user._id, type: 'deposit', amount, date: istTime });

        res.json({ message: 'Deposit successful', balance: user.balance });

    } catch (error) {
        console.error("❌ Deposit error:", error.message);
        res.status(500).json({ error: 'Deposit error' });
    }
});


app.post('/withdraw', authenticate, async (req, res) => {
    try {
        const { amount, ...extraFields } = req.body;

        // ✅ Validate Amount & Extra Fields
        if (!amount || isNaN(amount) || amount <= 0 || Object.keys(extraFields).length > 0) {
            return res.status(400).json({ error: 'Only a valid amount is accepted' });
        }

        console.log("🔍 Received withdrawal request. User ID:", req.user.id);

        // ✅ Check if req.user.id exists
        if (!req.user.id || !mongoose.Types.ObjectId.isValid(req.user.id)) {
            console.log("❌ Invalid or missing user ID:", req.user.id);
            return res.status(400).json({ error: "Invalid or missing user ID" });
        }

        const user = await User.findById(req.user.id);
        if (!user) {
            console.log("❌ User not found in DB.");
            return res.status(404).json({ error: "User not found" });
        }

        if (user.balance < amount) {
            console.log("❌ Insufficient funds. Balance:", user.balance, "Requested:", amount);
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        // ✅ Start a transaction session
        const session = await mongoose.startSession();
        session.startTransaction();

        try {
            // ✅ Update Balance & Store Transaction
            user.balance -= amount;
            await user.save({ session });

            const istTime = moment().tz("Asia/Kolkata").format();
            await Transaction.create([{ userId: user._id, type: 'withdraw', amount, date: istTime }], { session });

            // ✅ Commit transaction
            await session.commitTransaction();
            session.endSession();

            console.log("✅ Withdrawal successful. New Balance:", user.balance);
            res.json({ message: 'Withdrawal successful', balance: user.balance });

        } catch (error) {
            console.error("❌ Withdrawal transaction error:", error.message);
            await session.abortTransaction();
            session.endSession();
            res.status(500).json({ error: 'Withdrawal error' });
        }

    } catch (error) {
        console.error("❌ Withdrawal error:", error.message);
        res.status(500).json({ error: 'Withdrawal error' });
    }
});


app.post('/transfer', authenticate, async (req, res) => {
    const session = await mongoose.startSession(); // ✅ Start a session
    session.startTransaction();

    try {
        console.log("🟢 Received Transfer Request:", req.body);
        const { accountNumber: recipientAccount, amount } = req.body;

        // ✅ Validate Input
        if (!recipientAccount || typeof recipientAccount !== 'string' || isNaN(amount) || amount <= 0) {
            console.log("❌ Invalid recipient account number or amount");
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json({ error: 'Invalid recipient account number or amount' });
        }

        // ✅ Ensure User ID is Valid
        if (!req.user.id || !mongoose.Types.ObjectId.isValid(req.user.id)) {
            console.log("❌ Invalid or missing sender user ID:", req.user.id);
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json({ error: "Invalid or missing user ID" });
        }

        const formattedAccount = String(recipientAccount).trim();

        console.log("🔍 Fetching sender details...");
        const sender = await User.findById(req.user.id).session(session);
        if (!sender) {
            console.log("❌ Sender not found!");
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json({ error: 'Sender not found' });
        }

        if (sender.accountNumber === formattedAccount) {
            console.log("❌ Sender is trying to transfer to their own account.");
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json({ error: 'Cannot transfer to your own account' });
        }

        console.log("🔍 Fetching recipient details...");
        const recipient = await User.findOne({ accountNumber: formattedAccount }).session(session);
        if (!recipient) {
            console.log("❌ Recipient not found!");
            await session.abortTransaction();
            session.endSession();
            return res.status(404).json({ error: 'Recipient not found' });
        }

        console.log("💰 Checking sender balance:", sender.balance);
        if (sender.balance < amount) {
            console.log("❌ Insufficient funds! Sender balance:", sender.balance, "Transfer amount:", amount);
            await session.abortTransaction();
            session.endSession();
            return res.status(400).json({ error: 'Insufficient funds' });
        }

        console.log("💳 Updating balances...");
        sender.balance -= amount;
        recipient.balance += amount;

        await sender.save({ session });
        await recipient.save({ session });

        console.log(`✅ Balances updated! Sender: ${sender.balance}, Recipient: ${recipient.balance}`);

        // ✅ Store Transaction with IST Timestamp
        const istTime = moment().tz("Asia/Kolkata").format();
        await Transaction.create([
            { userId: sender._id, type: 'transfer', amount, date: istTime },
            { userId: recipient._id, type: 'deposit', amount, date: istTime }
        ], { session });

        await session.commitTransaction(); // ✅ Commit transaction
        session.endSession();

        console.log("✅ Transfer successful.");
        res.json({ message: 'Transfer successful', senderBalance: sender.balance });

    } catch (error) {
        console.error("❌ Transfer error:", error.message);
        await session.abortTransaction();
        session.endSession();
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

        // Enforce password security policy
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters long' });
        }

        // Find user
        const user = await User.findById(req.user.id); // Changed from req.userId to req.user.id
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

        // ⚠️ Invalidate old tokens (if you implement a token blacklist or refresh token system)
        // await TokenBlacklist.create({ token: oldToken });

        res.json({ message: 'Password updated successfully. Please log in again.' });

    } catch (error) {
        console.error('❌ Password change error:', error);
        res.status(500).json({ error: 'Password update failed' });
    }
});


// Delete Account Route
app.delete('/delete-account', authenticate, async (req, res) => {
    try {
        // Ensure the logged-in user is trying to delete their own account (this should already be ensured by the authenticate middleware)
        const user = await User.findById(req.user.id); // Changed from req.userId to req.user.id
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete the user's account
        await User.findByIdAndDelete(req.user.id); // Changed from req.userId to req.user.id

        // Delete any transactions related to the user
        await Transaction.deleteMany({ userId: req.user.id }); // Changed from req.userId to req.user.id

        // Respond with success
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
        const transactions = await Transaction.find({ userId: req.user.id }); // Changed from req.userId to req.user.id

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


app.post('/activate', async (req, res) => {
    try {
        const { cifNumber, username, dob } = req.body;
        const user = await User.findOne({ cifNumber, username, dob });

        if (!user) return res.status(404).json({ error: 'User not found' });
        if (user.isActivated) return res.status(400).json({ error: 'User already activated' });

        user.isActivated = true;
        await user.save();

        res.json({ message: 'User activated successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Activation failed' });
    }
});

app.put('/lock-user', async (req, res) => {
    const { adminUsername, adminPassword, accountNumber } = req.body;

    if (!adminUsername || !adminPassword || !accountNumber) {
        return res.status(400).json({ error: 'Admin credentials and target account number are required.' });
    }

    try {
        // Fetch the admin user from the database
        const adminUser = await mongoose.connection.db.collection('users').findOne({ username: adminUsername });

        if (!adminUser) {
            return res.status(404).json({ error: 'Admin user not found.' });
        }

        const isAdminPasswordValid = await bcrypt.compare(adminPassword, adminUser.password);
        if (!isAdminPasswordValid) {
            return res.status(400).json({ error: 'Invalid admin password.' });
        }

        // Ensure the user has an admin role
        if (adminUser.role !== 'admin') {
            return res.status(403).json({ error: 'Permission denied. Only admins can lock user accounts.' });
        }

        // Fetch the target user by account number
        const targetUser = await mongoose.connection.db.collection('users').findOne({ accountNumber });

        if (!targetUser) {
            return res.status(404).json({ error: 'Target user not found.' });
        }

        if (targetUser.isLocked) {
            return res.status(400).json({ error: 'User account is already locked.' });
        }

        // Lock the target user account
        await mongoose.connection.db.collection('users').updateOne(
            { accountNumber },
            { $set: { isLocked: true } }
        );

        res.json({ message: `User account with account number ${accountNumber} has been locked by admin ${adminUsername}.` });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.put('/unlock-user', async (req, res) => {
    const { adminUsername, adminPassword, accountNumber } = req.body;

    if (!adminUsername || !adminPassword || !accountNumber) {
        return res.status(400).json({ error: 'Admin credentials and target account number are required.' });
    }

    try {
        // Fetch the admin user from the database
        const adminUser = await mongoose.connection.db.collection('users').findOne({ username: adminUsername });

        if (!adminUser) {
            return res.status(404).json({ error: 'Admin user not found.' });
        }

        const isAdminPasswordValid = await bcrypt.compare(adminPassword, adminUser.password);
        if (!isAdminPasswordValid) {
            return res.status(400).json({ error: 'Invalid admin password.' });
        }

        // Ensure the user has an admin role
        if (adminUser.role !== 'admin') {
            return res.status(403).json({ error: 'Permission denied. Only admins can unlock user accounts.' });
        }

        // Fetch the target user by account number
        const targetUser = await mongoose.connection.db.collection('users').findOne({ accountNumber });

        if (!targetUser) {
            return res.status(404).json({ error: 'Target user not found.' });
        }

        if (!targetUser.isLocked) {
            return res.status(400).json({ error: 'User account is not locked.' });
        }

        // Unlock the target user account
        await mongoose.connection.db.collection('users').updateOne(
            { accountNumber },
            { $set: { isLocked: false } }
        );

        res.json({ message: `User account with account number ${accountNumber} has been unlocked by admin ${adminUsername}.` });

    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/forgot-password', async (req, res) => {
    try {
        const { accountNumber, username, mobileNumber, cifNumber } = req.body;

        // 🔍 Validate Input
        if (!accountNumber || !username || !mobileNumber || !cifNumber) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // 🔍 Find User by Provided Details
        const user = await User.findOne({ accountNumber, username, mobileNumber, cifNumber });

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // 🔑 Generate a Temporary Password (or OTP)
        const tempPassword = Math.random().toString(36).slice(-8); // Example: "a1b2c3d4"
        const hashedPassword = await bcrypt.hash(tempPassword, 10);

        // 📝 Update User Password (or send OTP)
        user.password = hashedPassword;
        await user.save();

        // ✅ Response (In Production, Send via Email/SMS Instead)
        res.json({ message: 'Temporary password generated. Please change it immediately.', tempPassword });

    } catch (error) {
        console.error('Forgot Password Error:', error);
        res.status(500).json({ error: 'Forgot password request failed' });
    }
});

// Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
