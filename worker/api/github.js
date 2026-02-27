import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class GitHubAuth {
    constructor(env) {
        this.clientId = env.GITHUB_CLIENT_ID;
        this.clientSecret = env.GITHUB_CLIENT_SECRET;
        this.redirectUri = `${env.WORKER_URL}/api/auth/github/callback`;
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 生成 GitHub 授权 URL
     */
    getAuthorizationUrl(state) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            scope: 'user', // 请求所有用户信息权限（包含 profile 和 email）
            state: state,
        });
        return `https://github.com/login/oauth/authorize?${params.toString()}`;
    }

    /**
     * 用 code 换取 access token
     */
    async getAccessToken(code) {
        const url = 'https://github.com/login/oauth/access_token';
        const body = {
            client_id: this.clientId,
            client_secret: this.clientSecret,
            code,
            redirect_uri: this.redirectUri,
        };

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
                body: JSON.stringify(body),
            });
        } catch (err) {
            console.error('GitHub token 请求网络错误:', err);
            throw new Error('GitHub 授权服务器连接失败');
        }

        // 检查 HTTP 状态和响应类型
        const contentType = response.headers.get('content-type') || '';
        if (!response.ok || !contentType.includes('application/json')) {
            const errorText = await response.text();
            console.error('GitHub token 响应异常', {
                status: response.status,
                statusText: response.statusText,
                headers: Object.fromEntries(response.headers),
                body: errorText.slice(0, 500),
            });
            throw new Error(`GitHub 授权失败 (HTTP ${response.status})`);
        }

        let data;
        try {
            data = await response.json();
        } catch (err) {
            console.error('解析 GitHub token 响应 JSON 失败:', err);
            throw new Error('GitHub 返回了无效的响应格式');
        }

        if (data.error) {
            console.error('GitHub token 错误响应:', data);
            throw new Error(data.error_description || data.error || 'GitHub 认证失败');
        }

        return data.access_token;
    }

    /**
     * 用 access token 获取用户信息（同时尝试获取邮箱）
     */
    async getUserInfo(accessToken) {
        // 获取用户基本信息
        let userResponse;
        try {
            userResponse = await fetch('https://api.github.com/user', {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    Accept: 'application/json',
                },
            });
        } catch (err) {
            console.error('GitHub 用户信息请求网络错误:', err);
            throw new Error('获取 GitHub 用户信息失败');
        }

        const userContentType = userResponse.headers.get('content-type') || '';
        if (!userResponse.ok || !userContentType.includes('application/json')) {
            const errorText = await userResponse.text();
            console.error('GitHub 用户信息响应异常', {
                status: userResponse.status,
                body: errorText.slice(0, 500),
            });
            throw new Error(`获取 GitHub 用户信息失败 (HTTP ${userResponse.status})`);
        }

        let userData;
        try {
            userData = await userResponse.json();
        } catch (err) {
            console.error('解析 GitHub 用户信息 JSON 失败:', err);
            throw new Error('GitHub 返回了无效的用户信息格式');
        }

        // 如果基本信息中没有 email，尝试从 /user/emails 获取
        if (!userData.email) {
            try {
                const emailsResponse = await fetch('https://api.github.com/user/emails', {
                    headers: { Authorization: `Bearer ${accessToken}` },
                });
                if (emailsResponse.ok) {
                    const emails = await emailsResponse.json();
                    const primary = emails.find((e) => e.primary && e.verified);
                    userData.email = primary ? primary.email : null;
                } else {
                    console.warn('获取用户邮箱列表失败:', emailsResponse.status);
                }
            } catch (err) {
                console.warn('获取用户邮箱列表异常:', err);
            }
        }

        // 如果仍然没有邮箱，则抛出错误（可根据业务决定是否允许无邮箱的用户）
        if (!userData.email) {
            throw new Error('无法获取 GitHub 用户的公开邮箱，请确保邮箱在 GitHub 中设置为公开');
        }

        return {
            githubId: userData.id.toString(),
            username: userData.login,
            email: userData.email,
            name: userData.name || userData.login,
            avatar: userData.avatar_url,
            bio: userData.bio || '',
        };
    }

    /**
     * 处理 GitHub 登录回调：获取用户信息，关联或创建本地用户，生成会话 token
     */
    async handleGitHubLogin(code, state) {
        // 1. 获取 access token
        const accessToken = await this.getAccessToken(code);

        // 2. 获取用户信息
        const githubUser = await this.getUserInfo(accessToken);

        // 3. 检查是否已存在 GitHub 关联
        let userId = await this.db.getUserIdByGitHub(githubUser.githubId);
        let user = null;

        if (userId) {
            // 已有 GitHub 关联，直接获取用户
            user = await this.db.getUserById(userId);
        } else if (githubUser.email) {
            // 尝试通过邮箱查找现有用户
            user = await this.db.getUserByEmail(githubUser.email);

            if (user) {
                // 存在邮箱相同的用户，关联 GitHub
                await this.db.createGitHubUser(githubUser.githubId, user.id);
                // 更新头像（可选）
                await this.db.updateUser(user.id, {
                    avatar: user.avatar || githubUser.avatar,
                    githubId: githubUser.githubId,
                });
            } else {
                // 不存在，创建新用户
                const randomPassword = crypto.randomUUID() + Math.random();
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                user = await this.db.createUser({
                    username: githubUser.username,
                    email: githubUser.email,
                    password: hashedPassword,
                    role: 'user',
                    avatar: githubUser.avatar,
                    bio: githubUser.bio,
                    githubId: githubUser.githubId,
                });

                await this.db.createGitHubUser(githubUser.githubId, user.id);
            }
        } else {
            // 没有邮箱，无法创建用户（理论上前面已抛出异常，但保留兜底）
            throw new Error('无法获取 GitHub 用户邮箱');
        }

        // 4. 创建会话
        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}