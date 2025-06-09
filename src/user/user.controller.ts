import { Controller } from '@nestjs/common';
import { UserService } from './user.service';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
export class UserController {
  constructor(private readonly userService: UserService) {}

  @MessagePattern('user.findUserById')
  async findUserById(userId: string) {
    return await this.userService.findUserById(userId);
  }
}
