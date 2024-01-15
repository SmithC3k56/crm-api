import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';

export class SignUpDto extends PartialType(CreateUserDto) {}
