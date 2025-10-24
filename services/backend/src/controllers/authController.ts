import { Request, Response, NextFunction } from 'express';
import AuthService from '../services/authService';
import { User } from '../types/user';
import inputUtils from '../utils/input';


const ping = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;
  try {
    return res.json({"msg":"ok" });
  } catch (err) {
    next(err);
  }
};

const login = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password } = req.body;
  try {
    const user = await AuthService.authenticate(username, password);
    const token = await AuthService.generateJwt(user.id);
    return res.json({ token, user });
  } catch (err) {
    next(err);
  }
};

const forgotPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { email } = req.body;
  try {
    await AuthService.sendResetPasswordEmail(email);
    // 204: no content, but client knows email was sent
    return res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const resetPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { username, token, newPassword } = req.body;
  try {
    await AuthService.resetPassword(username, token, newPassword);
    return res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const setPassword = async (req: Request, res: Response, next: NextFunction) => {
  const { username, token, newPassword } = req.body;
  try {
    await AuthService.setPassword(username, token, newPassword);
    return res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

const createUser = async (req: Request, res: Response, next: NextFunction) => {
  const { username, password, email, first_name, last_name } = req.body;
  try {
    // Campos requeridos.
    if (!username || !password || !email || !first_name || !last_name) {
      return res.status(422).json("Faltan datos.");
    }

    // Verificar que son datos válidos.
    if (!inputUtils.isValidUsername(username)
    || !inputUtils.isValidEmail(email)
    || !inputUtils.isValidName(first_name)
    || !inputUtils.isValidName(last_name)) {
      return res.status(400).json("Los datos no están en el formato requerido.");
    }
    
    // Quitar espacios en blanco (a excepción de la contraseña).
    const user: User = {
      username: username.trim(),
      password,
      email: email.trim(),
      first_name: first_name.trim(),
      last_name: last_name.trim()
    };
    const userDB = await AuthService.createUser(user);
    return res.status(201).json(userDB);
  } catch (err) {
    next(err);
  }
};

const updateUser = async (req: Request, res: Response, next: NextFunction) => {
  const userId = req.params.id;
  const { username, password, email, first_name, last_name } = req.body;
  try {
  const user: User = {
      username,
      password,
      email,
      first_name,
      last_name
    };
    const userDB = await AuthService.updateUser(user);
      return res.status(201).json(userDB);
  } catch (err) {
    next(err);
  }
};

/*
export const getProfile = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const user = await UserService.getById(req.user!.id);
    res.json(user);
  } catch (err) {
    next(err);
  }
};

export const updateProfile = async (req: Request, res: Response, next: NextFunction) => {
  const { firstName, lastName } = req.body;
  try {
    const updated = await UserService.updateProfile(req.user!.id, { firstName, lastName });
    res.json(updated);
  } catch (err) {
    next(err);
  }
};

export const getPicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const { stream, contentType } = await FileService.getProfilePicture(req.user!.id);
    res.setHeader('Content-Type', contentType);
    stream.pipe(res);
  } catch (err) {
    next(err);
  }
};

export const uploadPicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded' });
    }
    const url = await FileService.saveProfilePicture(req.user!.id, req.file);
    res.json({ url });
  } catch (err) {
    next(err);
  }
};

export const deletePicture = async (req: Request, res: Response, next: NextFunction) => {
  try {
    await FileService.deleteProfilePicture(req.user!.id);
    res.sendStatus(204);
  } catch (err) {
    next(err);
  }
};

*/



export default {
  ping,
  login,
  forgotPassword,
  resetPassword,
  setPassword,
  createUser,
  updateUser,
};