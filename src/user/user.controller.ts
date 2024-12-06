import {Controller, Get, Param, Patch, Post} from '@nestjs/common';
import {UserService} from "./user.service";

@Controller('api/user/')
export class UserController {
    constructor(private readonly userService: UserService) {}

    @Get('/all')
    get_all() {
        return this.userService.get_all();
    }

    @Get('/:id')
    get_by_id(@Param('id') id: string) {
        return this.userService.get_by_id(id);
    }

    @Patch('/:id/update')
    update() {
        return this.userService.update();
    }
}
