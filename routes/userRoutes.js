import express from "express";
import bcrypt from "bcrypt";
import User from "../models/User.js";
import jwt from "jsonwebtoken";

const router = express.Router();

// Middleware
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
router.post("/add", async (req, res) => {

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

// Get Users
router.get("/", verifyToken, async (req, res) => {
  const users = await User.find();
  res.status(200).json(users);
});

// Get User by ID
router.get("/:id", verifyToken, async (req, res) => {
  const user = await User.findById(req.params.id);
  
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado!" });
  }

  res.status(200).json(user);
});

// Login
router.post("/login", async (req, res) => {

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
  const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, process.env.JWT_SECRET);

  res.status(200).json({ token });

});

// Update User
router.put("/:id", verifyToken, async (req, res) => {

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

  // Verifica se o usuário existe
  const existUser = await User.findById(req.params.id);

  if (!existUser) {
    return res.status(422).json({ msg: "Usuário não existe!" });
  }

  // Criptografa a senha
  const salt = await bcrypt.genSalt(16);
  const hash = await bcrypt.hash(password.pass, salt);

  // Atualiza o usuário
  existUser.name = name;
  existUser.email = email;
  existUser.password = hash;
  existUser.role = role;
  existUser.sector = sector;
  existUser.systems = systems;

  try {
    await existUser.save();
    res.status(200).json({ msg: "Usuário atualizado com sucesso!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Erro ao atualizar usuário!" });
  }

});

// Delete User
router.delete("/:id", verifyToken, async (req, res) => {

  // Verifica se o usuário existe
  const existUser = await User.findById(req.params.id);

  if (!existUser) {
    return res.status(422).json({ msg: "Usuário não existe!" });
  }

  try {
    await existUser.remove();
    res.status(200).json({ msg: "Usuário deletado com sucesso!" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Erro ao deletar usuário!" });
  }
});

export default router;