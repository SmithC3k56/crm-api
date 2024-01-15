import { Body, Post, Controller } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from 'src/user/dto/sign-up.dto';
import { SignInDto } from 'src/user/dto/sign-in.dto';

@Controller('auth')
export class AuthController {
  constructor(private authenService: AuthService) {}

  @Post('/signup')
  signup(@Body() signUpDto: SignUpDto): Promise<{ token: string }> {
    return this.authenService.signup(signUpDto);
  }
  @Post('/signin')
  signin(@Body() loginDto: SignInDto): Promise<{ token: string }> {
    return this.authenService.signin(loginDto);
  }
}
