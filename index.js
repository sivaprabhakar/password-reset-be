
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRoutes = require('./routes/authRoutes');

const app = express();
const PORT = process.env.PORT || 8000;

app.use(express.json());
app.use(cors());

mongoose.connect('mongodb+srv://sivaprabhakaran94:Siva153@cluster0.zl5zlfx.mongodb.net/');

app.use('/api', authRoutes);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
