import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { MicroserviceOptions, Transport } from '@nestjs/microservices';
import { envs } from './config/envs';
import { ValidationPipe } from '@nestjs/common';
import { CustomRpcException } from './interfaces/ErrorResponse';

async function bootstrap() {
  const app = await NestFactory.createMicroservice<MicroserviceOptions>(
    AppModule,
    {
      transport: Transport.NATS,
      options: {
        servers: envs.nats.servers,
      },
    },
  );

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      exceptionFactory: (errors) => {
        const formattedErrors = errors.map((error) => ({
          property: error.property,
          value: error.value,
          constraints: error.constraints || {},
        }));

        const messages = errors.map((error) => {
          return `${error.property} has wrong value ${error.value}. ${Object.values(
            error.constraints || {},
          ).join(', ')}`;
        });

        throw new CustomRpcException(
          400,
          messages,
          'Validation Error',
          formattedErrors,
        );
      },
    }),
  );

  await app.listen();
}
void bootstrap();
