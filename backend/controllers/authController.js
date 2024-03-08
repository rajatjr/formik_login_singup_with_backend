const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/User');

exports.signup = async (req, res) => {
  try {
    const {firstname, lastname, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ firstname, lastname, email, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User created successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
};


exports.login = async (req, res) => {
    try {
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(401).json({ message: 'Authentication failed' });
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Authentication failed' });
      }
      const secretKey = process.env.JWT_SECRET_KEY; // Replace "your_secret_key" with your actual secret key
      const token = jwt.sign({ userId: user._id, email: user.email }, secretKey, { expiresIn: '1h' });
      res.status(200).json({ message: 'Authentication successful', token });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  };
