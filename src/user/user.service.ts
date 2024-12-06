import { Injectable } from '@nestjs/common';

@Injectable()
export class UserService {
    get_all() {
        return 'All users';
    }

    get_by_id(id: string) {
        return `User with ID: ${id}`;
    }

    update() {
        return 'Profile updated successfully';
    }
}
