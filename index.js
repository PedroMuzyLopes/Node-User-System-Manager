import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

import dotenv from "dotenv";
dotenv.config();

// Models
import User from "./models/User.js";

const app = express();

app.use(cors());
app.use(express.json());


function verifyToken(req, res, next) {
  const bearerHeader = req.headers["authorization"];

  if (typeof bearerHeader !== "undefined") {
    const bearer = bearerHeader.split(" ");
    const bearerToken = bearer[1];
    
    try {
      req.token = jwt.verify(bearerToken, process.env.JWT_SECRET);
      next();
    } catch (err) {
      res.status(403).json({ msg: "Token inválido!"});
    }
  } else {
    res.status(401).json({msg: "Acesso negado!"});
  }
}


// Register User
app.post("/user/add", async (req, res) => {

  const { name, email, password, role, sector, systems } = req.body;

  // Verifica se os dados vieram vazios
  if (!name) {
    return res.status(422).json({ msg: "Você deve informar um nome!" });
  }
  if (!email) {
    return res.status(422).json({ msg: "Você deve informar um email!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Você deve informar uma senha!" });
  }
  if (password.pass !== password.confirm) {
    return res.status(422).json({ msg: "As senhas digitadas devem ser iguais!" });
  }
  if (!role) {
    return res.status(422).json({ msg: "Você deve informar um cargo!" });
  }
  if (!sector) {
    return res.status(422).json({ msg: "Você deve informar um setor!" });
  }

  // Verifica se o usuário já existe
  const existUser = await User.findOne({ email });

  if (existUser) {
    return res.status(422).json({ msg: "Usuário já existe no banco de dados!" });
  }

  // Criptografa a senha
  const salt = await bcrypt.genSalt(16);
  const hash = await bcrypt.hash(password.pass, salt);

  // Cria o usuário
  const user = new User({ name, email, password: hash, role, sector, systems });

  try {
    await user.save();
    res.status(200).json({ msg: "Usuário criado com sucesso!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Erro ao criar usuário!" });
  }

});

// Login
app.post("/user/login", async (req, res) => {

  const { email, password } = req.body;

  // Verifica se os dados vieram vazios
  if (!email) {
    return res.status(422).json({ msg: "Você deve informar um email!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "Você deve informar uma senha!" });
  }

  // Verifica se o usuário existe
  const user = await User.findOne({ email });

  if (!user) {
    return res.status(422).json({ msg: "Usuário não existe!" });
  }

  // Verifica se a senha está correta
  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(422).json({ msg: "Senha incorreta!" });
  }

  // Gera o token
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

  res.status(200).json({ token });

});

// Get Users
app.get("/user", verifyToken, async (req, res) => {
  const users = await User.find();
  res.status(200).json(users);
});

// Database
mongoose.connect(process.env.MONGO_URL)
  .then(() => {
    console.log('Conectado ao MongoDB');
    app.listen(8098);
  })
  .catch(err => {
    console.log(err);
  })