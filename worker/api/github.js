import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class GitHubAuth {
    constructor(env) {
        this.clientId = env.GITHUB_CLIENT_ID;
        this.clientSecret = env.GITHUB_CLIENT_SECRET;
        this.redirectUri = `${env.WORKER_URL}/api/auth/github/callback`;
        this.db = new Database(env.BLOG_KV);
    }

// 在 getAuthorizationUrl 方法中，将 scope 改为 'user'
getAuthorizationUrl(state) {
    const params = new URLSearchParams({
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        scope: 'user',  // 请求所有用户信息权限
        state: state
    });
    return `https://github.com/login/oauth/authorize?${params.toString()}`;
}

    async getAccessToken(code) {
        let response;
        try {
            response = await fetch('https://github.com/login/oauth/access_token', {
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
        } catch (fetchError) {
            console.error('GitHub token 请求网络错误:', fetchError);
            throw new Error('GitHub 授权服务器连接失败');
        }

        const contentType = response.headers.get('content-type');
        if (!response.ok || !contentType || !contentType.includes('application/json')) {
            const errorText = await response.text();
            console.error('GitHub token 响应异常:', {
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers),
                body: errorText.substring(0, 500)
            });
            throw new Error(`GitHub 授权失败 (HTTP ${response.status})`);
        }

        let data;
        try {
            data = await response.json();
        } catch (jsonError) {
            console.error('解析 GitHub token 响应 JSON 失败:', jsonError);
            throw new Error('GitHub 返回了无效的响应格式');
        }

        if (data.error) {
            console.error('GitHub token 错误:', data);
            throw new Error(data.error_description || data.error || 'GitHub 认证失败');
        }

        return data.access_token;
    }

    async getUserInfo(accessToken) {
        let response;
        try {
            response = await fetch('https://api.github.com/user', {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
        } catch (fetchError) {
            console.error('GitHub 用户信息请求网络错误:', fetchError);
            throw new Error('获取 GitHub 用户信息失败');
        }

        const contentType = response.headers.get('content-type');
        if (!response.ok || !contentType || !contentType.includes('application/json')) {
            const errorText = await response.text();
            console.error('GitHub 用户信息响应异常:', {
                status: response.status,
                body: errorText.substring(0, 500)
            });
            throw new Error(`获取 GitHub 用户信息失败 (HTTP ${response.status})`);
        }

        let userData;
        try {
            userData = await response.json();
        } catch (jsonError) {
            console.error('解析 GitHub 用户信息 JSON 失败:', jsonError);
            throw new Error('GitHub 返回了无效的用户信息格式');
        }

        // 如果主要用户信息中没有 email，尝试获取 emails（需要 user:email 权限）
        if (!userData.email) {
            try {
                const emailsResponse = await fetch('https://api.github.com/user/emails', {
                    headers: { 'Authorization': `Bearer ${accessToken}` }
                });
                if (emailsResponse.ok) {
                    const emails = await emailsResponse.json();
                    const primaryEmail = emails.find(email => email.primary && email.verified);
                    userData.email = primaryEmail ? primaryEmail.email : null;
                } else {
                    console.error('获取用户 emails 失败:', emailsResponse.status);
                }
            } catch (emailError) {
                console.error('获取用户 emails 异常:', emailError);
            }
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
                // 已有账号，关联 GitHub
                await this.db.createGitHubUser(githubUser.githubId, user.id);
                await this.db.updateUser(user.id, {
                    githubId: githubUser.githubId,
                    avatar: user.avatar || githubUser.avatar
                });
            } else {
                // 创建新用户
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