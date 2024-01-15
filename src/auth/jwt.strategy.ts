import { Injectable, UnauthorizedException } from "@nestjs/common";
import { PassportStrategy } from "@nestjs/passport";
import { InjectRepository } from "@nestjs/typeorm";
import { Strategy, ExtractJwt } from 'passport-jwt';
import { User } from "src/user/entities/user.entity";
import { Repository } from "typeorm";

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
 constructor(
  @InjectRepository(User)
  private userReponsitory: Repository<User>,
 ) {
  super({
   jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
   secretOrKey: process.env.JWT_SECRET,
  });


  async validate(payload: any){
   const { id } = payload;

   const user = await this.userReponsitory.findOne({
    where: { id: id },
   });

   if (!user) {
    throw new UnauthorizedException('Login first to access this endpoint.');
   }
   return user;
  }



 }
}