import express from "express";
import {
  getUsers,
  getUser,
  addUser,
  deleteUser,
  updateUser,
} from "../controllers/user.js";
import db from "../database.js";

const router = express.Router();

// Middleware to handle database connection
const withDBConnection = async (req, res, next) => {
  try {
    req.db = db; 
    next();
  } catch (error) {
    console.error("Error establishing a database connection:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

router.get("/", withDBConnection, getUsers);
router.get("/:id", withDBConnection, getUser);
router.post("/", withDBConnection, addUser);
router.delete("/:id", withDBConnection, deleteUser);
router.put("/:id", withDBConnection, updateUser);

export default router; 