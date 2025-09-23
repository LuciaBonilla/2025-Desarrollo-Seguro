// knexfile.ts
import type { Knex } from 'knex';
import dotenv from 'dotenv';

dotenv.config();

const config: { [key: string]: Knex.Config } = {
  development: {
    client: 'pg',
    connection: {
      //host: process.env.DB_HOST || 'localhost',
      host: process.env.DB_HOST,
      //user: process.env.DB_USER || 'user',
      user: process.env.DB_USER,
      //password: process.env.DB_PASS || 'password', // CWE-259
      password: process.env.DB_PASS, 
      //database: process.env.DB_NAME || 'jwt_api',
      database: process.env.DB_NAME,
      port: parseInt(process.env.DB_PORT || '5432'),
    },
    migrations: {
      directory: '../migrations',
    },
    seeds: {
      directory: '../seeds',
    },
  },
};

export default config;
