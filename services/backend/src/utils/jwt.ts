
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET is missing or too weak.');
}


const generateToken = (userId: string) => {
  return jwt.sign(
    { id: userId },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
};


const verifyToken = (token: string) => {
  return jwt.verify(token, JWT_SECRET);
};

export default {
  generateToken,
  verifyToken
}