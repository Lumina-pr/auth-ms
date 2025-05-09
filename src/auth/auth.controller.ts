import { Body, Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { MessagePattern, Payload } from '@nestjs/microservices';
import { CustomRpcException } from 'src/interfaces/ErrorResponse';
import { RegisterUserDto } from './dto/register-user.dto';
import { LoginUserDto } from './dto/login-user.dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDto: RegisterUserDto) {
    return this.authService.registerUser(registerUserDto);
  }

  @MessagePattern('auth.login.user')
  async loginUser(@Payload() loginUserDto: LoginUserDto) {
    const user = await this.authService.validateUser(loginUserDto);
    if (!user) {
      throw new CustomRpcException(401, 'Unauthorized');
    }
    return this.authService.login(user.id.toString());
  }

  @MessagePattern('auth.verify.user')
  verifyUser(@Payload() token: string) {
    return this.authService.verifyUser(token);
  }
}
