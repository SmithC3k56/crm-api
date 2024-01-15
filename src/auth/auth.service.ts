import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from 'src/user/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { SignUpDto } from 'src/user/dto/sign-up.dto';
import * as bcrypt from 'bcryptjs';
import { SignInDto } from 'src/user/dto/sign-in.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private userRespository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async signup(signUpDto: SignUpDto): Promise<{ token: string }> {
    const { name, email, password } = signUpDto;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await this.userRespository.create({
      name,
      email,
      password: hashedPassword,
    });

    await this.userRespository.save(user);

    const token = this.jwtService.sign({ id: user.id });

    return token;
  }

  async signin(signinDto: SignInDto): Promise<{ token: string }> {
    const { email, password } = signinDto;
    const user = await this.userRespository.findOne({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const isPasswordMatched = await bcrypt.compare(password, user.password);

    if (isPasswordMatched) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const token = this.jwtService.sign({ id: user.id });

    return { token };
  }
  
}
