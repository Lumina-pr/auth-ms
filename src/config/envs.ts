import 'dotenv/config';
import * as joi from 'joi';

interface EnvVars {
  PORT: number;
  NATS_SERVERS: string[];
  DATABASE_URL: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
}

const envsSchema = joi
  .object({
    PORT: joi.number().required(),
    NATS_SERVERS: joi.array().items(joi.string()).required(),
    DATABASE_URL: joi.string().required(),
    JWT_SECRET: joi.string().required(),
    JWT_EXPIRES_IN: joi.string().required(),
  })
  .unknown(true);

const { error, value } = envsSchema.validate({
  ...process.env,
  NATS_SERVERS: process.env.NATS_SERVERS?.split(','),
});

if (error) {
  throw new Error(`Config validation error: ${error.message}`);
}

const envVars: EnvVars = value;

export const envs = {
  port: envVars.PORT,
  nats: {
    servers: envVars.NATS_SERVERS,
  },
  databaseUrl: envVars.DATABASE_URL,
  jwtSecret: envVars.JWT_SECRET,
  jwtExpiresIn: envVars.JWT_EXPIRES_IN,
};
