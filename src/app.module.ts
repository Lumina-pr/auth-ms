import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { envs } from './config/envs';
import { UserModule } from './user/user.module';
import { UserController } from './user/user.controller';

@Module({
  imports: [AuthModule, MongooseModule.forRoot(envs.databaseUrl), UserModule],
  controllers: [UserController],
})
export class AppModule {}
