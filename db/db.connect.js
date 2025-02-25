const mongoose = require("mongoose");

require("dotenv").config();

const MONGOURI = process.env.MONGODB;

const initialiseDatabase = async () => {
  await mongoose
    .connect(MONGOURI)
    .then(() => {
      console.log("Connected to DB");
    })
    .catch((e) => console.log("Unable to connect to DB", e));
};

module.exports = { initialiseDatabase };
