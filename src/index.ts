import express, { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config(); // Load variables from .env or Railway's variables

const prisma = new PrismaClient();
const app = express();
const port = process.env.PORT || 3000;

// Ensure JWT_SECRET is set; if not, throw an error
const envJwtSecret = process.env.JWT_SECRET;
if (!envJwtSecret) {
  throw new Error("JWT_SECRET is missing in environment variables!");
}
const JWT_SECRET: string = envJwtSecret;

app.use(express.json());

// ---------------------------
// Type Declarations
// ---------------------------
interface JwtPayload {
  userId: string;
}

interface AuthRequest extends Request {
  userId?: string;
}

// ---------------------------
// Auth Middleware
// ---------------------------
function requireAuth(req: AuthRequest, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Authorization header missing" });

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    // Type Guard: Check if decoded is an object and has a userId
    if (typeof decoded === "object" && decoded !== null && "userId" in decoded) {
      req.userId = (decoded as JwtPayload).userId;
      return next();
    }
    return res.status(401).json({ error: "Invalid token payload" });
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(401).json({ error: "Token verification failed" });
  }
}

// ---------------------------
// Auth Routes
// ---------------------------

// Register a new user
app.post("/auth/register", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    // Check if the user already exists
    const existing = await prisma.user.findUnique({ where: { email } });
    if (existing) return res.status(409).json({ error: "Email already registered" });

    // Hash the password and create a new user
    const hashed = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
      data: { email, password: hashed },
    });
    res.status(201).json({ id: user.id, email: user.email });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Log in an existing user
app.post("/auth/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    // Create a JWT that expires in 7 days
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get the current authenticated user's info
app.get("/auth/me", requireAuth, async (req: AuthRequest, res: Response) => {
  try {
    if (!req.userId) return res.status(401).json({ error: "User not authenticated" });
    const user = await prisma.user.findUnique({ where: { id: req.userId } });
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({ id: user.id, email: user.email });
  } catch (error) {
    console.error("Error fetching user details:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ---------------------------
// Root Route
// ---------------------------
app.get("/", (_req: Request, res: Response) => {
  res.send(`
    <h1>TypeScript Auth API</h1>
    <p>Available Routes:</p>
    <ul>
      <li>POST /auth/register</li>
      <li>POST /auth/login</li>
      <li>GET  /auth/me (requires Authorization header)</li>
    </ul>
  `);
});

// ---------------------------
// Start Server
// ---------------------------
app.listen(Number(port), "0.0.0.0", () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
