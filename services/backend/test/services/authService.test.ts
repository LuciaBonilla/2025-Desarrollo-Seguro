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
    expect(nodemailer.createTransport().sendMail).toHaveBeenCalledWith({
      to: user.email,
      subject: 'Activate your account',
      html: expect.stringContaining('Click <a href="')
    });
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
    expect(getUserChain.where).toHaveBeenCalledWith({email : 'username'});
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
    await expect(AuthService.authenticate('username', 'password123')).rejects.toThrow('Invalid email or not activated');
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
      invite_token_expires: null
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

/*
  Repertorio de tests para verificar que las vulnerabilidades halladas en el
  práctico 2 fueron mitigadas.
*/
describe('AuthService.security', () => {
  beforeEach (() => {
    jest.resetModules();
    jest.clearAllMocks();

  });

    /*
    *Descripción:
      Prueba unitaria que valida la mitigación del Template Code Injection
      identificado en la funcionalidad de envío de correo al crear un nuevo
      usuario.

    *Procedimiento:
      Para validar la mitigación se verifica que el contenido del correo de
      creación de cuenta no tenga el resultado de la ejecución del código pasado
      como entrada de usuario, o bien que el correo no sea creado ante esa
      entrada maliciosa.

    *Función a testear: AuthService.createUser(user: User)
    *Locación: services\backend\src\services\authService.ts

    *Entrada:
      Un usuario con first_name: '<%= {4*4} %>'
      Esta entrada se utiliza porque el código a testear ejecuta funciones del paquete de npm:
      'ejs' (Embedded JavaScript templates).
      Más información en: https://www.npmjs.com/package/ejs

    *Resultado positivo:
      Dada la entrada, no se crea un correo con el valor 16,
      lo cual significa que el código NO es ejecutado en el lado del servidor.

    *Resultado negativo:
      Dada la entrada, se crea un correo con el valor 16,
      lo cual significa que el código SÍ es ejecutado en el lado del servidor.

    * La función se basa en el test 'createUser' provisto por los profesores;
      se utilizó ese test y se hicieron modificaciones.

    * Se empleó la documentación de JEST: https://jestjs.io/docs/next/api

    * Además, se uso la ayuda de ChatGPT para entender a profundidad el código brindado por los profesores.

    * Funciones utilizadas de JEST:
    * test(name, fn, timeout)                         -> https://jestjs.io/docs/next/api#testname-fn-timeout
    * jest.fn(implementation?)                        -> https://jestjs.io/docs/next/mock-function-api#jestfnimplementation
    * jest.fn().mockReturnThis()                      -> https://jestjs.io/docs/next/mock-function-api#mockfnmockreturnthis
    * jest.fn().mockResolvedValue(value)              -> https://jestjs.io/docs/next/mock-function-api#mockfnmockresolvedvaluevalue
    * jest.fn().mockReturnValue(value)                -> https://jestjs.io/docs/next/mock-function-api#mockfnmockreturnvaluevalue
    * mockedDb.mockReturnValueOnce(value)             -> https://jestjs.io/docs/next/mock-function-api#mockfnmockreturnvalueoncevalue
    * expect(value)                                   -> https://jestjs.io/docs/next/expect#expectvalue
    * expect().toHaveBeenCalledWith(arg1, arg2, ...)  -> https://jestjs.io/docs/next/expect#tohavebeencalledwitharg1-arg2-
    * expect.any(constructor)                         -> https://jestjs.io/docs/next/expect#expectanyconstructor
    * jest.fn().mock.calls                            -> https://jestjs.io/docs/next/mock-function-api#mockfnmockcalls
    * expect().not                                    -> https://jestjs.io/docs/next/mock-function-api#mockfnmockcalls
    * expect().toContain(item)                        -> https://jestjs.io/docs/next/expect#tocontainitem
    */
    test('No Template Code Injection in create user mail', async () => {
      // ***Entrada:
      const user  = {
        id: 'user-123',
        email: 'a@a.com',
        password: 'password123',
        first_name: '<%= {4*4} %>', // Entrada maliciosa.
        last_name: 'Last',
        username: 'username',
      } as User;

      // ***Preparación de funciones Mock (simulaciones de las funciones verdaderas) de la base de datos de mentira y de la de envío de correo.
      
      // 1. Simula un select en el que no existe usuario, es decir, se simula que crea por primera vez el usuario.
      const selectChain = {
        where: jest.fn().mockReturnThis(),        // Retorna undefined cuando se llama a la función .where({ username: user.username }) en la función a testear.
        orWhere: jest.fn().mockReturnThis(),      // Al igual que where, retorna undefined cuando se llama a la función .orWhere({ email: user.email }) en la función a testear.
        first: jest.fn().mockResolvedValue(null)  // Retorna null cuando se llama a la función .first() en la función a testear, porque simula que el usuario aún no está creado.
      };

      // 2. Simula un insert exitoso del usuario.
      const insertChain = {
        insert: jest.fn().mockResolvedValue([user]) // Retorna los datos del usuario cuando se llama a la función .insert({datos del usuario}) en la función a testear.
      };

      // 3. Simula la función asociada al envío de correo.
      const transporter = { sendMail: jest.fn().mockResolvedValue({}) };       // Retorna {}, porque no interesa lo que retorna sino lo que recibe (el contenido del email).
      (nodemailer.createTransport as jest.Mock).mockReturnValue(transporter);  // Simula la función de envío de correo.   

      // 4. Asocia las funciones Mock a la base de datos de mentira; se ejecutarán en cadena (primero el select y luego el insert).
      mockedDb
      .mockReturnValueOnce(selectChain as any)
      .mockReturnValueOnce(insertChain as any);

      // *** Ejecución: Ejecuta el método a testear (se ejecutarán las funciones Mock, en lugar de las verdaderas).
      await AuthService.createUser(user);

      // *** Verificación:
      // 1. Verifica que la base de datos de mentira realizó el insert con los parámetros dados.
      expect(insertChain.insert).toHaveBeenCalledWith({
        email: user.email,
        password: expect.any(String),           // Sólo basta saber si es un string.
        first_name: user.first_name,
        last_name: user.last_name,
        username: user.username,
        activated: false,
        invite_token: expect.any(String),       // Sólo basta saber si es un string.
        invite_token_expires: expect.any(Date)  // Sólo basta saber si es una fecha.
      });

      // 2. Verificación del contenido del correo.
      if (transporter.sendMail.mock.calls.length === 0) {
        // 2.1. Email no creado (lo cual también está OK).
        expect(transporter.sendMail).not.toHaveBeenCalled();
      } else {
        // 2.2. Verifica que a la función de enviar email no le haya llegado el html con el código ejecutado.
        const [mail] = transporter.sendMail.mock.calls[0];
        expect(mail.html).not.toContain('16');                 // Verifica que el código no se haya ejecutado.
        expect(mail.html).toContain('&lt;%= {4*4} %&gt;');     // Verifica que la entrada maliciosa haya sido sanitizada.
      }
  }
  );
});