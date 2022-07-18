import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

const app = express();
app.use(cors());
app.use(express.json());

// Variáveis de ambiente
dotenv.config();

// Routes
import userRoutes from "./routes/userRoutes.js";
app.use("/user", userRoutes);

// Database
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log('Conectado ao MongoDB');
    app.listen(8098);
  })
  .catch(err => {
    console.log(err);
  })