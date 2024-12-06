import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
    signin() {
        return 'User signed in successfully';
    }

    signup() {
        return 'User signed up successfully';
    }

    sign_out() {
        return 'User signed out successfully';
    }
}
