const mongoose = require('mongoose');

require('dotenv').config();

exports.connect = () => {
    mongoose.connect(process.env.MONGODB_URL)
    .then(() => {console.log("DB connected successfully")})
    .catch((e) => {
        console.error("DB connection problem", e);
        process.exit(1);
    });
};