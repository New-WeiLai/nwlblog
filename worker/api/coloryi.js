import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class ColoryiAuth {
    constructor(env) {
        this.clientId = env.COLORYI_CLIENT_ID;
        this.clientSecret = env.COLORYI_CLIENT_SECRET;
        // 回调地址必须与注册时一致
        this.redirectUri = `${env.WORKER_URL}/api/auth/coloryi/callback`;
        this.authEndpoint = 'https://blog.coloryi.top/oauth/authorize';
        this.tokenEndpoint = 'https://blog.coloryi.top/oauth/token';
        this.userInfoEndpoint = 'https://blog.coloryi.top/api/user/info';
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 生成 Coloryi 授权 URL
     */
    getAuthorizationUrl(state) {
        const params = new URLSearchParams({
            client_id: this.clientId,
            redirect_uri: this.redirectUri,
            response_type: 'code',
            scope: 'profile',
            state: state
        });
        return `${this.authEndpoint}?${params.toString()}`;
    }

    /**
     * 用 code 换取 access_token
     */
    async getAccessToken(code) {
        const params = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: this.redirectUri,
            client_id: this.clientId,
            client_secret: this.clientSecret
        });

        let response;
        try {
            response = await fetch(this.tokenEndpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: params
            });
        } catch (err) {
            console.error('Coloryi token 请求网络错误:', err);
            throw new Error('Coloryi 服务器连接失败');
        }

        const contentType = response.headers.get('content-type') || '';
        if (!response.ok) {
            let errorMsg = `Coloryi 授权失败 (HTTP ${response.status})`;
            if (contentType.includes('application/json')) {
                try {
                    const errorData = await response.json();
                    errorMsg = errorData.error || errorMsg;
                } catch (e) {}
            }
            throw new Error(errorMsg);
        }

        if (!contentType.includes('application/json')) {
            throw new Error('Coloryi 返回了无效的响应格式');
        }

        const data = await response.json();
        if (!data.access_token) {
            throw new Error('未获取到访问令牌');
        }
        return data;
    }

    /**
     * 获取用户信息
     */
    async getUserInfo(accessToken) {
        let response;
        try {
            response = await fetch(this.userInfoEndpoint, {
                headers: { 'Authorization': `Bearer ${accessToken}` }
            });
        } catch (err) {
            console.error('Coloryi 用户信息请求失败:', err);
            throw new Error('获取 Coloryi 用户信息失败');
        }

        if (!response.ok) {
            throw new Error(`获取用户信息失败 (HTTP ${response.status})`);
        }

        const userData = await response.json();
        return {
            coloryiId: userData.id || userData.sub, // Coloryi 的用户唯一标识
            username: userData.name || userData.username,
            email: userData.email,
            avatar: userData.avatar || userData.picture
        };
    }

    /**
     * 处理 Coloryi 登录回调
     */
    async handleCallback(code, state) {
        // 1. 换取令牌
        const tokenData = await this.getAccessToken(code);
        const accessToken = tokenData.access_token;

        // 2. 获取用户信息
        const coloryiUser = await this.getUserInfo(accessToken);

        // 3. 检查是否已存在 Coloryi 关联
        let userId = await this.db.getUserIdByColoryi(coloryiUser.coloryiId);
        let user = null;

        if (userId) {
            user = await this.db.getUserById(userId);
        } else if (coloryiUser.email) {
            user = await this.db.getUserByEmail(coloryiUser.email);
            if (user) {
                // 关联现有用户
                await this.db.createColoryiUser(coloryiUser.coloryiId, user.id);
                if (!user.avatar && coloryiUser.avatar) {
                    await this.db.updateUser(user.id, { avatar: coloryiUser.avatar });
                }
            }
        }

        if (!user) {
            // 创建新用户
            const randomPassword = crypto.randomUUID();
            const hashedPassword = await bcrypt.hash(randomPassword, 10);

            // 生成唯一用户名
            let username = coloryiUser.username || `coloryi_${coloryiUser.coloryiId.slice(0, 8)}`;
            let existingUser = await this.db.getUserByUsername(username);
            if (existingUser) {
                username = `${username}_${Math.random().toString(36).substring(2, 6)}`;
            }

            user = await this.db.createUser({
                username,
                email: coloryiUser.email || null,
                password: hashedPassword,
                role: 'user',
                avatar: coloryiUser.avatar || null,
                bio: ''
            });

            await this.db.createColoryiUser(coloryiUser.coloryiId, user.id);
        }

        // 4. 创建会话
        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}