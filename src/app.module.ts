import { Module } from '@nestjs/common';
import { AuthModule } from './auth/auth.module';
import { MongooseModule } from '@nestjs/mongoose';
import { envs } from './config/envs';
import { UserModule } from './user/user.module';

@Module({
  imports: [AuthModule, MongooseModule.forRoot(envs.databaseUrl), UserModule],
})
export class AppModule {}
