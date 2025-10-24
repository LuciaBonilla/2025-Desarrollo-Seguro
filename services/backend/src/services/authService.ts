
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import db from '../db';
import { User,UserRow } from '../types/user';
import jwtUtils from '../utils/jwt';
import hashUtils from '../utils/hash'
import ejs from 'ejs';

const RESET_TTL = 1000 * 60 * 60;         // 1h
const INVITE_TTL = 1000 * 60 * 60 * 24 * 7; // 7d

class AuthService {

  static async createUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ username: user.username })
      .orWhere({ email: user.email })
      .first();
    if (existing) throw new Error('User already exists with that username or email');
    // create invite token
    const invite_token = crypto.randomBytes(6).toString('hex');
    const invite_token_expires = new Date(Date.now() + INVITE_TTL);

    // Hashear la contraseña y el token de activación de cuenta.
    const hashed_input_password = await hashUtils.hashPlainText(user.password);
    const hashed_invite_token = await hashUtils.hashPlainText(invite_token);
    
    await db<UserRow>('users')
      .insert({
        username: user.username,
        password: hashed_input_password, // Guardar el dato hasheado en la base de datos.
        email: user.email,
        first_name: user.first_name,
        last_name:  user.last_name,
        invite_token: hashed_invite_token, // Guardar el dato hasheado en la base de datos.
        invite_token_expires,
        activated: false
      });
      // send invite email using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });
    const link = `${process.env.FRONTEND_URL}/activate-user?token=${invite_token}&username=${user.username}`;
   
    // Usar etiquetas <%=  %>
    const template = `
      <html>
        <body>
          <h1>Hello <%= user.first_name %> <%= user.last_name %></h1>
          <p>Click <a href="<%= link %>">here</a> to activate your account.</p>
        </body>
      </html>
    `;
    // Pasar las variables como parámetros.
    const htmlBody = ejs.render(template, { user, link });
    
    await transporter.sendMail({
      from: "info@example.com",
      to: user.email,
      subject: 'Activate your account',
      html: htmlBody
    });
  }

  static async updateUser(user: User) {
    const existing = await db<UserRow>('users')
      .where({ id: user.id })
      .first();
    if (!existing) throw new Error('User not found');

    // Hashear la contraseña.
    const hashed_input_password = await hashUtils.hashPlainText(user.password);

    await db<UserRow>('users')
      .where({ id: user.id })
      .update({
        username: user.username,
        password: hashed_input_password, // Guardar el dato hasheado en la base de datos.
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name
      });
    return existing;
  }

  static async authenticate(username: string, password: string) {
    const user = await db<UserRow>('users')
      .where({ username })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('Invalid email or not activated');

    // Comparar.
    const hashed_saved_password = user.password; // El dato viene de la base de datos.
    const is_authenticated = await hashUtils.compareHashedPlainText(
      password, // Contraseña que da el usuario en texto plano.
      hashed_saved_password);

    if (is_authenticated != true) throw new Error('Invalid password');
    return user;
  }

  static async sendResetPasswordEmail(email: string) {
    const user = await db<UserRow>('users')
      .where({ email })
      .andWhere('activated', true)
      .first();
    if (!user) throw new Error('No user with that email or not activated');

    const token = crypto.randomBytes(6).toString('hex');
    const expires = new Date(Date.now() + RESET_TTL);

    // Hashear el token de reseteo de contraseña.
    const hashed_reset_password_token = await hashUtils.hashPlainText(token)

    await db('users')
      .where({ id: user.id })
      .update({
        reset_password_token: hashed_reset_password_token, // Guardar el dato hasheado en la base de datos.
        reset_password_expires: expires
      });

    // send email with reset link using nodemailer and local SMTP server
    const transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
    await transporter.sendMail({
      to: user.email,
      subject: 'Your password reset link',
      html: `Click <a href="${link}">here</a> to reset your password.`
    });
  }

  static async resetPassword(username: string, token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where({ username })
      .andWhere('reset_password_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired reset token');

    // Comparar tokens (el no hasheado y el que está en la base de datos hasheado).
    const ok = await hashUtils.compareHashedPlainText(token, row.reset_password_token);
    if (!ok) throw new Error('Invalid or expired reset token');

    // Hashear contraseña.
    const hashed_input_password = await hashUtils.hashPlainText(newPassword);

    await db('users')
      .where({ id: row.id })
      .update({
        password: hashed_input_password, // Guardar el dato hasheado en la base de datos.
        reset_password_token: null,
        reset_password_expires: null
      });
  }

  static async setPassword(username: string, token: string, newPassword: string) {
    const row = await db<UserRow>('users')
      .where({ username })
      .andWhere('invite_token_expires', '>', new Date())
      .first();
    if (!row) throw new Error('Invalid or expired invite token');

    // Comparar token (el no hasheado y el que está en la base de datos hasheado).
    const ok = await hashUtils.compareHashedPlainText(token, row.invite_token);
    if (!ok) throw new Error('Invalid or expired invite token');

    // Hashear contraseña.
    const hashed_input_password = await hashUtils.hashPlainText(newPassword)

    await db('users')
      .update({
        password: hashed_input_password, // Guardar el dato hasheado en la base de datos.
        invite_token: null,
        invite_token_expires: null,
        activated: true
      })
      .where({ id: row.id });
  }

  static generateJwt(userId: string): string {
    return jwtUtils.generateToken(userId);
  }
}

export default AuthService;
