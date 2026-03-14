import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class OldChatAuth {
    constructor(env) {
        this.apiBase = env.OLDCHAT_API_BASE || 'http://60.205.94.101:8080';
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 直接转发前端请求体给 OldChat，不添加任何额外头
     * @param {Object} payload - 前端发送的完整请求体
     * @returns {Promise<Object>} OldChat 返回的数据
     */
    async callOldChatLogin(payload) {
        const url = `${this.apiBase}/v1/auth/login`;

        // 只保留最基本的 Content-Type 头，其余由浏览器默认
        const headers = {
            'Content-Type': 'application/json'
        };

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers: headers,
                body: JSON.stringify(payload) // 直接转发，不修改 payload
            });
        } catch (err) {
            console.error('OldChat 登录请求网络错误:', err);
            throw new Error('OldChat 服务器连接失败');
        }

        // 记录原始响应（用于调试）
        const responseText = await response.text();
        console.log('OldChat 原始响应:', {
            status: response.status,
            headers: Object.fromEntries(response.headers),
            body: responseText.substring(0, 500)
        });

        // 尝试解析 JSON
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (err) {
            // 非 JSON 响应，根据状态码给出提示
            if (response.status === 403 || response.status === 401) {
                throw new Error('OldChat 账号或密码错误，请检查');
            } else {
                throw new Error(`OldChat 服务返回了非 JSON 响应 (HTTP ${response.status})`);
            }
        }

        // 如果状态码不是 2xx，但返回了 JSON 错误
        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP ${response.status}`;
            throw new Error(errorMsg);
        }

        return data;
    }

    /**
     * 处理 OldChat 登录，使用完整 payload 调用 OldChat
     * @param {Object} payload - 前端发送的完整请求体
     * @returns {Promise<Object>} 本地用户和会话 token
     */
    async handleLogin(payload) {
        // 1. 调用 OldChat 登录，直接转发 payload
        const oldchatData = await this.callOldChatLogin(payload);
        const oldchatUser = oldchatData.user;
        const oldchatUid = oldchatUser.uid;

        // 2. 检查是否已存在 OldChat 关联
        let userId = await this.db.getUserIdByOldChat(oldchatUid);
        let user = null;

        if (userId) {
            user = await this.db.getUserById(userId);
        } else {
            // 尝试通过邮箱查找现有用户
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
                // 创建新用户
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

        // 3. 创建博客会话
        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}