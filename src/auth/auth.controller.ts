import {Controller, Get, Post} from '@nestjs/common';
import {AuthService} from "./auth.service";

@Controller('api/auth/')
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @Post('signin')
    signin() {
        return this.authService.signin();
    }

    @Post('signup')
    signup() {
        return this.authService.signup();
    }

    @Get("/sign-out")
    sign_out() {
        return this.authService.sign_out();
    }
}
