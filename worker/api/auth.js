import { Database, ROLES } from '../utils/db.js';
import { EmailService } from '../utils/email.js';
import { GitHubAuth } from './github.js';
import bcrypt from 'bcryptjs';

export class AuthAPI {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
        this.emailService = new EmailService(env);
        this.githubAuth = new GitHubAuth(env);
    }

    async sendVerificationCode(email, type = 'register') {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) throw new Error('邮箱格式不正确');

        if (type === 'register') {
            const existingUser = await this.db.getUserByEmail(email);
            if (existingUser) throw new Error('该邮箱已被注册');
        }

        const code = await this.db.createVerificationCode(email, type);
        await this.emailService.sendVerificationCode(email, code, type === 'register' ? '注册' : '重置密码');
        return { message: '验证码已发送' };
    }

    async verifyCode(email, code, type = 'register') {
        await this.db.verifyCode(email, code, type);
        return { message: '验证成功' };
    }

    async register(username, email, password, code) {
        const isVerified = await this.db.isEmailVerified(email, 'register');
        if (!isVerified) await this.db.verifyCode(email, code, 'register');

        const existingUser = await this.db.getUserByUsername(username);
        if (existingUser) throw new Error('用户名已存在');

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await this.db.createUser({
            username, email, password: hashedPassword, role: ROLES.USER
        });

        await this.db.clearVerification(email);
        const token = await this.db.createSession(user.id);
        return { user, token };
    }

    async login(email, password) {
        const user = await this.db.getUserByEmail(email);
        if (!user) throw new Error('用户不存在');
        if (!user.isActive) throw new Error('账号已被禁用');

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) throw new Error('密码错误');

        await this.db.updateUser(user.id, { lastLogin: new Date().toISOString() });
        const token = await this.db.createSession(user.id);
        return { user, token };
    }

    async forgotPassword(email) {
        const user = await this.db.getUserByEmail(email);
        if (!user) throw new Error('用户不存在');

        const token = await this.db.createPasswordResetToken(email);
        await this.emailService.sendPasswordResetEmail(email, token);
        return { message: '重置密码邮件已发送' };
    }

    async resetPassword(email, token, newPassword, code) {
        const isVerified = await this.db.isEmailVerified(email, 'reset_password');
        if (!isVerified) await this.db.verifyCode(email, code, 'reset_password');

        await this.db.verifyPasswordResetToken(email, token);

        const user = await this.db.getUserByEmail(email);
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        await this.db.updateUser(user.id, { password: hashedPassword });
        await this.db.markPasswordResetUsed(email);
        await this.db.clearVerification(email);

        return { message: '密码重置成功' };
    }

    getGitHubAuthUrl(state) {
        return this.githubAuth.getAuthorizationUrl(state);
    }

    async handleGitHubCallback(code, state) {
        return await this.githubAuth.handleGitHubLogin(code, state);
    }

    async logout(token) {
        await this.db.deleteSession(token);
        return { message: '已登出' };
    }

    async getCurrentUser(token) {
        const session = await this.db.getSession(token);
        if (!session) throw new Error('未登录');

        const user = await this.db.getUserById(session.userId);
        if (!user || !user.isActive) throw new Error('用户不存在或已被禁用');
        return user;
    }
}