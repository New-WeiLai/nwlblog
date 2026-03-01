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
            scope: 'read:user user:email', // 请求所有用户信息
            state: state,
        });
        return `https://github.com/login/oauth/authorize?${params.toString()}`;
    }

    /**
     * 用 code 换取 access token（增强错误处理）
     */
    async getAccessToken(code) {
        let response;
        try {
            response = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Accept: 'application/json',
                },
                body: JSON.stringify({
                    client_id: this.clientId,
                    client_secret: this.clientSecret,
                    code,
                    redirect_uri: this.redirectUri,
                }),
            });
        } catch (fetchError) {
            console.error('GitHub token 请求网络错误:', fetchError);
            throw new Error('GitHub 授权服务器连接失败');
        }

        const contentType = response.headers.get('content-type') || '';
        // 处理 HTTP 错误状态
        if (!response.ok) {
            let errorMsg = `GitHub 授权失败 (HTTP ${response.status})`;
            if (contentType.includes('application/json')) {
                try {
                    const errorData = await response.json();
                    errorMsg = errorData.error_description || errorData.error || errorMsg;
                } catch (e) {
                    // 忽略解析错误
                }
            } else {
                const errorText = await response.text();
                errorMsg += `: ${errorText.substring(0, 200)}`;
            }
            console.error('GitHub token 错误:', { status: response.status, body: errorMsg });
            throw new Error(errorMsg);
        }

        if (!contentType.includes('application/json')) {
            const errorText = await response.text();
            console.error('GitHub token 响应非 JSON:', errorText.substring(0, 500));
            throw new Error('GitHub 返回了无效的响应格式');
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

    /**
     * 用 access token 获取用户信息（优先邮箱）
     */
    async getUserInfo(accessToken) {
        let response;
        try {
            response = await fetch('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${accessToken}` },
            });
        } catch (fetchError) {
            console.error('GitHub 用户信息请求网络错误:', fetchError);
            throw new Error('获取 GitHub 用户信息失败');
        }

        const contentType = response.headers.get('content-type') || '';
        if (!response.ok) {
            let errorMsg = `获取 GitHub 用户信息失败 (HTTP ${response.status})`;
            if (contentType.includes('application/json')) {
                try {
                    const errorData = await response.json();
                    errorMsg = errorData.message || errorMsg;
                } catch (e) {}
            }
            throw new Error(errorMsg);
        }

        if (!contentType.includes('application/json')) {
            throw new Error('GitHub 返回了无效的用户信息格式');
        }

        let userData;
        try {
            userData = await response.json();
        } catch (jsonError) {
            console.error('解析 GitHub 用户信息 JSON 失败:', jsonError);
            throw new Error('GitHub 返回了无效的用户信息格式');
        }

        // 获取邮箱（如果主信息中没有）
        if (!userData.email) {
            try {
                const emailsResponse = await fetch('https://api.github.com/user/emails', {
                    headers: { Authorization: `Bearer ${accessToken}` },
                });
                if (emailsResponse.ok) {
                    const emails = await emailsResponse.json();
                    // 优先 primary && verified，其次任意 verified
                    const verifiedEmail = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
                    userData.email = verifiedEmail ? verifiedEmail.email : null;
                } else {
                    console.warn('获取用户邮箱列表失败:', emailsResponse.status);
                }
            } catch (emailError) {
                console.warn('获取用户邮箱列表异常:', emailError);
            }
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

        // 3. 检查是否已存在 GitHub 关联（通过关联表）
        let userId = await this.db.getUserIdByGitHub(githubUser.githubId);
        let user = null;

        if (userId) {
            // 已有 GitHub 关联，直接获取用户
            user = await this.db.getUserById(userId);
        } else if (githubUser.email) {
            // 尝试通过邮箱查找现有用户
            user = await this.db.getUserByEmail(githubUser.email);

            if (user) {
                // 存在邮箱相同的用户，建立 GitHub 关联（不更新用户表内的 githubId）
                await this.db.createGitHubUser(githubUser.githubId, user.id);
                // 可选：更新用户头像（如果用户没有设置过头像）
                if (!user.avatar) {
                    await this.db.updateUser(user.id, { avatar: githubUser.avatar });
                }
            } else {
                // 不存在，创建新用户（不存 githubId）
                const randomPassword = crypto.randomUUID(); // 简化随机密码
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                user = await this.db.createUser({
                    username: githubUser.username,
                    email: githubUser.email,
                    password: hashedPassword,
                    role: 'user',
                    avatar: githubUser.avatar,
                    bio: githubUser.bio,
                    // 注意：此处不再传入 githubId
                });

                // 建立 GitHub 关联
                await this.db.createGitHubUser(githubUser.githubId, user.id);
            }
        } else {
            // 无法获取邮箱，拒绝创建用户（可根据业务调整）
            throw new Error('无法获取 GitHub 用户邮箱，请确保在 GitHub 中设置了公开邮箱');
        }

        // 4. 创建会话
        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}