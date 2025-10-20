import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';

import AuthService from '../../src/services/authService';
import db from '../../src/db';
import { User } from '../../src/types/user';

jest.mock('../../src/db')
const mockedDb = db as jest.MockedFunction<typeof db>

// mock the nodemailer module
jest.mock('nodemailer');
const mockedNodemailer = nodemailer as jest.Mocked<typeof nodemailer>;

// mock send email function
mockedNodemailer.createTransport = jest.fn().mockReturnValue({
  sendMail: jest.fn().mockResolvedValue({ success: true }),
});

describe('AuthService.generateJwt', () => {
  const OLD_ENV = process.env;
  beforeEach (() => {
    jest.resetModules();
    jest.clearAllMocks();

  });

  it('createUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;

    // mock no user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user
    };
    // Mock the database insert
    const insertChain = {
      returning: jest.fn().mockResolvedValue([user]),
      insert: jest.fn().mockReturnThis()
    };
    mockedDb
    .mockReturnValueOnce(selectChain as any)
    .mockReturnValueOnce(insertChain as any);

    // Call the method to test
    await AuthService.createUser(user);

    // Verify the database calls
    expect(insertChain.insert).toHaveBeenCalledWith({
      email: user.email,
      password: user.password,
      first_name: user.first_name,
      last_name: user.last_name,
      username: user.username,
      activated: false,
      invite_token: expect.any(String),
      invite_token_expires: expect.any(Date)
    });

    expect(nodemailer.createTransport).toHaveBeenCalled();
    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith(expect.objectContaining({
      from: "info@example.com",
      to: user.email,
      subject: 'Activate your account',
      html: expect.stringContaining('Click <a href=')
    }));
  }
  );

  it('createUser already exist', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      orWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user) // Existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.createUser(user)).rejects.toThrow('User already exists with that username or email');
  });

  it('updateUser', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@b.com',
      password: 'newpassword123',
      first_name: 'NewFirst',
      last_name: 'NewLast',
      username: 'newusername',
    } as User;
    // mock user exists
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({ id: user.id }) // Existing user found
    };
    // Mock the database update
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(user) // Update successful
    };
    mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    const updatedUser = await AuthService.updateUser(user);
    // Verify the database calls
    expect(selectChain.where).toHaveBeenCalledWith({ id: user.id });
    expect(updateChain.update).toHaveBeenCalled();
  });

  it('updateUser not found', async () => {
    const user  = {
      id: 'user-123',
      email: 'a@a.com',
      password: 'password123',
      first_name: 'First',
      last_name: 'Last',
      username: 'username',
    } as User;
    // mock user not found
    const selectChain = {
      where: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null) // No existing user found
    };
    mockedDb.mockReturnValueOnce(selectChain as any);
    // Call the method to test
    await expect(AuthService.updateUser(user)).rejects.toThrow('User not found');
  });

  it('authenticate', async () => {
    const email = 'username';
    const password = 'password123';

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    const user = await AuthService.authenticate(email, password);
    expect(getUserChain.where).toHaveBeenCalledWith({username : 'username'});
    expect(user).toBeDefined();
  });

  it('authenticate wrong pass', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({password:'otherpassword'}),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid password');
  });

  it('authenticate wrong user', async () => {

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    // Mock the database update password
    mockedDb.mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid username or not activated');
  });

  it('sendResetPasswordEmail', async () => {
    const email = 'a@a.com';
    const user = {
      id: 'user-123',
      email: email,
    };
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(user),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any); 
    // Call the method to test
    await AuthService.sendResetPasswordEmail(email);
    expect(getUserChain.where).toHaveBeenCalledWith({ email });
    expect(updateChain.update).toHaveBeenCalledWith({
      reset_password_token: expect.any(String),
      reset_password_expires: expect.any(Date)
    });
    expect(mockedNodemailer.createTransport).toHaveBeenCalled();
    expect(mockedNodemailer.createTransport().sendMail).toHaveBeenCalledWith({
      to: user.email,
      subject: 'Your password reset link',
      html: expect.stringContaining('Click <a href="')
    });
  });

  it('sendResetPasswordEmail no mail', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };

    mockedDb
      .mockReturnValueOnce(getUserChain as any);

    // Call the method to test
    await expect(AuthService.sendResetPasswordEmail('a@a.com')).rejects.toThrow('No user with that email or not activated');
  });

  it('resetPassword', async () => {
    const token = 'valid-token';
    const newPassword = 'newpassword123';    
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue({id: 'user-123'}),
    };
    // Mock the database update password
    const updateChain = {
      where: jest.fn().mockReturnThis(),
      update: jest.fn().mockResolvedValue(1)
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);
    // Call the method to test
    await AuthService.resetPassword(token, newPassword);
    expect(getUserChain.where).toHaveBeenCalledWith('reset_password_token', token);
    expect(updateChain.update).toHaveBeenCalledWith({
      password: newPassword,
      reset_password_token: null,
      reset_password_expires: null
    });
  });

  it('resetPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.resetPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired reset token');
  });

  it('setInitialPassword', async () => {
    const password = 'whatawonderfulpassword';
    const user_id = 'user-123';
    const token = 'invite-token';
    // Mock the database row
    const mockRow = {
      id: user_id,
      invite_token: token,
      invite_token_expires: new Date(Date.now() + 1000 * 60 * 60 * 24) // 1 day from now
    };

    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(mockRow),
    };

    // mock the database update password
    const updateChain = {
      where: jest.fn().mockResolvedValue(1),
      update: jest.fn().mockReturnThis()
    }

    mockedDb
      .mockReturnValueOnce(getUserChain as any)
      .mockReturnValueOnce(updateChain as any);

    // Call the method to test
    await AuthService.setPassword(token, password);

    // Verify the database calls
    expect(updateChain.update).toHaveBeenCalledWith({
      password: password,
      invite_token: null,
      invite_token_expires: null,
      activated:true
    });

    expect(updateChain.where).toHaveBeenCalledWith({ id: user_id });
  });

  it('setInitialPassword invalid token', async () => {
    // Mock the database get user
    const getUserChain = {
      where: jest.fn().mockReturnThis(),
      andWhere: jest.fn().mockReturnThis(),
      first: jest.fn().mockResolvedValue(null),
    };
    mockedDb
      .mockReturnValueOnce(getUserChain as any);
    // Call the method to test
    await expect(AuthService.setPassword('invalid-token', 'newpassword123')).rejects.toThrow('Invalid or expired invite token');
  });

  it('generateJwt', () => {
    const userId = 'abcd-1234';
    const token = AuthService.generateJwt(userId);

    // token should be a non-empty string
    expect(typeof token).toBe('string');
    expect(token.length).toBeGreaterThan(0);

    // verify the token decodes to our payload
    const decoded = jwt.verify(token,"secreto_super_seguro");
    expect((decoded as any).id).toBe(userId);
  });

});
