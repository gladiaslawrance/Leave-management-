import jwt from "jsonwebtoken";
import User from "../models/User.js";

export async function authenticate(req, res, next) {
  const authorization = req.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7) : "";

  if (!token) return res.status(401).json({ message: "Please sign in to continue." });

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    if (!payload.sub) return res.status(401).json({ message: "Invalid or expired session." });
    const user = await User.findById(payload.sub);
    if (!user) return res.status(401).json({ message: "Invalid or expired session." });
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
      return res.status(401).json({ message: "Invalid or expired session." });
    }
    next(error);
  }
}

export function requireRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.status(403).json({ message: "You are not allowed to perform this action." });
    next();
  };
}
