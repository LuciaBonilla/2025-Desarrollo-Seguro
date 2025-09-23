import jwt from 'jsonwebtoken';

const generateToken = (userId: string) => {
  return jwt.sign(
    { id: userId }, 
    "secreto_super_seguro", 
    { expiresIn: '1h' }
  );
};

const verifyToken = (token: string) => {
  return jwt.verify(token, "secreto_super_seguro");
};

export default {
  generateToken,
  verifyToken
}