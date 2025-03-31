import { HttpStatus, Injectable, Logger } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/schemas/user.schema';
import { UserService } from 'src/user/user.service';
import { CustomRpcException } from 'src/interfaces/ErrorResponse';
import * as bcrypt from 'bcryptjs';
import { RegisterUserDto } from './dto/register-user.dto';
import { JwtService } from '@nestjs/jwt';
import { envs } from 'src/config/envs';
import { LoginUserDto } from './dto/login-user.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly usersService: UserService,
    private jwtService: JwtService,
  ) {}

  async login(userid: string) {
    const payload = { sub: userid };

    return {
      access_token: await this.jwtService.signAsync(payload),
    };
  }

  async validateUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;
    const user = await this.usersService.findOne(email);
    if (user && bcrypt.compareSync(password, user.password)) {
      const userWithoutPassword = { id: user._id, email: user.email };
      return userWithoutPassword;
    }

    return null;
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const user = await this.usersService.findOne(registerUserDto.email);
    if (user) {
      throw new CustomRpcException(
        HttpStatus.BAD_REQUEST,
        'User with this email already exists',
      );
    }

    try {
      const newUser = await this.userModel.create({
        ...registerUserDto,
        password: bcrypt.hashSync(registerUserDto.password, 10),
      });

      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = newUser.toObject();
      return {
        userWithoutPassword,
        access_token: (await this.login(newUser._id.toString())).access_token,
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new CustomRpcException(400, error.message);
      }

      throw new CustomRpcException(500, 'Server Error');
    }
  }

  async verifyUser(token: string) {
    try {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { sub, ...rest } = this.jwtService.verify(token, {
        secret: envs.jwtSecret,
      });

      return {
        user: sub,
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        token: (await this.login(sub)).access_token,
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new CustomRpcException(400, error.message);
      }
      throw new CustomRpcException(500, 'Server Error');
    }
  }
}
