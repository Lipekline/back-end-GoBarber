import { getRepository, getTreeRepository } from 'typeorm';
import { compare } from 'bcryptjs';
import User from '../models/User';
import { sign } from 'jsonwebtoken';
import authConfig from '../config/auth'

interface Request {
    email: string;
    password: string;
}

interface Response { 
    user: User;
    token: string; 
}

class AuthenticateUserService {
    public async execute({ email, password }: Request): Promise<Response> {
        const usersRepository = getRepository(User);

        const user = await usersRepository.findOne({ where: { email } });

        if (!user){
            throw new Error('Incorrect email/password combination');
        }

        const passwordMatched = await compare(password, user.password);

        if (!passwordMatched){
            throw new Error('Incorrect email/password combination');
        }

        const { secret, expiresIn } = authConfig.jwt;

        const token = sign({ }, '342312a7b3eee6d9a17cbc4dd211c761', {
            subject: user.id,
            expiresIn,
        });

        return { user, token }
    }
}

export default AuthenticateUserService;