import express from "express";
import { seedQRData } from "../controllers/seedController.js";

const router = express.Router();

router.post("/seed", seedQRData);

export default router;
