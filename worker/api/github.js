import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class GitHubAuth {
    constructor(env) {
        this.clientId = env.GITHUB_CLIENT_ID;
        this.clientSecret = env.GITHUB_CLIENT_SECRET;
        this.redirectUri = `${env.SITE_URL}/api/auth/github/callback`;
        this.db = new Database(env.BLOG_KV);
    }

    getAuthorizationUrl(state) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: 'user:email',
            state: state
        });
        return `https://github.com/login/oauth/authorize?${params.toString()}`;
    }

    async getAccessToken(code) {
        const response = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                client_id: this.clientId,
                client_secret: this.clientSecret,
                code: code,
                redirect_uri: this.redirectUri
            })
        });

        const data = await response.json();
        if (data.error) throw new Error(data.error_description || 'GitHub认证失败');
        return data.access_token;
    }

    async getUserInfo(accessToken) {
        const response = await fetch('https://api.github.com/user', {
            headers: { 'Authorization': `Bearer ${accessToken}` }
        });
        
        const userData = await response.json();
        
        if (!userData.email) {
            const emailsResponse = await fetch('https://api.github.com/user/emails', {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
            const emails = await emailsResponse.json();
            const primaryEmail = emails.find(email => email.primary && email.verified);
            userData.email = primaryEmail ? primaryEmail.email : null;
        }

        return {
            githubId: userData.id.toString(),
            username: userData.login,
            email: userData.email,
            name: userData.name || userData.login,
            avatar: userData.avatar_url,
            bio: userData.bio || ''
        };
    }

    async handleGitHubLogin(code, state) {
        const accessToken = await this.getAccessToken(code);
        const githubUser = await this.getUserInfo(accessToken);

        let userId = await this.db.getUserIdByGitHub(githubUser.githubId);
        let user = null;

        if (userId) {
            user = await this.db.getUserById(userId);
        } else if (githubUser.email) {
            user = await this.db.getUserByEmail(githubUser.email);
            
            if (user) {
                await this.db.createGitHubUser(githubUser.githubId, user.id);
                await this.db.updateUser(user.id, {
                    githubId: githubUser.githubId,
                    avatar: user.avatar || githubUser.avatar
                });
            } else {
                const randomPassword = crypto.randomUUID() + Math.random();
                const hashedPassword = await bcrypt.hash(randomPassword, 10);
                
                user = await this.db.createUser({
                    username: githubUser.username,
                    email: githubUser.email,
                    password: hashedPassword,
                    role: 'user',
                    avatar: githubUser.avatar,
                    bio: githubUser.bio,
                    githubId: githubUser.githubId
                });
                
                await this.db.createGitHubUser(githubUser.githubId, user.id);
            }
        } else {
            throw new Error('无法获取GitHub邮箱');
        }

        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}