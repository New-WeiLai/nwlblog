import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class OldChatAuth {
    constructor(env) {
        this.apiBase = env.OLDCHAT_API_BASE || 'http://60.205.94.101:8080';
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 调用 OldChat 登录接口
     * @param {string} identifier - 用户名或邮箱
     * @param {string} password - 密码
     * @param {string} deviceId - 可选设备ID
     * @returns {Promise<Object>} OldChat 返回的用户信息和 token
     */
    async callOldChatLogin(identifier, password, deviceId = 'blog-service') {
        const url = `${this.apiBase}/v1/auth/login`;
        const payload = {
            identifier,
            password,
            device_id: deviceId,
            device_name: 'NwelyBlog',
            platform: 'web',
            app_version: '1.0.0'
        };

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } catch (err) {
            console.error('OldChat 登录请求网络错误:', err);
            throw new Error('OldChat 服务器连接失败');
        }

        // 先读取响应体为文本，避免多次读取
        const responseText = await response.text();

        let data;
        try {
            data = JSON.parse(responseText);
        } catch (err) {
            console.error('OldChat 响应非 JSON:', responseText.substring(0, 200));
            throw new Error('OldChat 返回了无效的响应格式');
        }

        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP ${response.status}`;
            const errorCode = data.code || 'unknown';
            console.error('OldChat 登录失败:', { status: response.status, error: errorMsg, code: errorCode });
            throw new Error(errorMsg);
        }

        return data; // 包含 access_token, refresh_token, user
    }

    /**
     * 处理 OldChat 登录：验证凭证，关联或创建本地用户，生成会话 token
     */
    async handleLogin(identifier, password, deviceId) {
        const oldchatData = await this.callOldChatLogin(identifier, password, deviceId);
        const oldchatUser = oldchatData.user;
        const oldchatUid = oldchatUser.uid;

        let userId = await this.db.getUserIdByOldChat(oldchatUid);
        let user = null;

        if (userId) {
            user = await this.db.getUserById(userId);
        } else {
            if (oldchatUser.email) {
                user = await this.db.getUserByEmail(oldchatUser.email);
            }

            if (user) {
                await this.db.createOldChatUser(oldchatUid, user.id);
                if (!user.avatar && oldchatUser.avatar_url) {
                    await this.db.updateUser(user.id, { avatar: oldchatUser.avatar_url });
                }
                if (!user.bio && oldchatUser.signature) {
                    await this.db.updateUser(user.id, { bio: oldchatUser.signature });
                }
            } else {
                const randomPassword = crypto.randomUUID();
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                let username = oldchatUser.username || `oldchat_${oldchatUid.slice(0, 8)}`;
                let existingUser = await this.db.getUserByUsername(username);
                if (existingUser) {
                    username = `${username}_${Math.random().toString(36).substring(2, 6)}`;
                }

                user = await this.db.createUser({
                    username,
                    email: oldchatUser.email || null,
                    password: hashedPassword,
                    role: 'user',
                    avatar: oldchatUser.avatar_url || null,
                    bio: oldchatUser.signature || null
                });

                await this.db.createOldChatUser(oldchatUid, user.id);
            }
        }

        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}