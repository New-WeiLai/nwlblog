import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class OldChatAuth {
    constructor(env) {
        this.apiBase = env.OLDCHAT_API_BASE || 'http://60.205.94.101:8080';
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 调用 OldChat 登录接口，直接转发前端请求体
     * @param {Object} payload - 前端发送的完整请求体
     * @returns {Promise<Object>} OldChat 返回的用户信息和 token
     */
    async callOldChatLogin(payload) {
        const url = `${this.apiBase}/v1/auth/login`;

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(payload) // 直接转发前端请求体
            });
        } catch (err) {
            console.error('OldChat 登录请求网络错误:', err);
            throw new Error('OldChat 服务器连接失败');
        }

        // 记录原始响应（调试用）
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
            // 非 JSON 响应
            if (response.status === 403) {
                throw new Error('OldChat 账号或密码错误，请检查');
            } else {
                throw new Error(`OldChat 服务返回了非 JSON 响应 (HTTP ${response.status})`);
            }
        }

        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP ${response.status}`;
            throw new Error(errorMsg);
        }

        return data;
    }

    /**
     * 处理 OldChat 登录：验证凭证，关联或创建本地用户，生成会话 token
     * @param {Object} payload - 前端发送的完整请求体（包含 identifier, password, device_id 等）
     * @returns {Promise<Object>} 包含本地用户和会话 token
     */
    async handleLogin(payload) {
        // 1. 调用 OldChat 登录，转发整个 payload
        const oldchatData = await this.callOldChatLogin(payload);
        const oldchatUser = oldchatData.user;
        const oldchatUid = oldchatUser.uid;

        // 2. 检查是否已存在 OldChat 关联
        let userId = await this.db.getUserIdByOldChat(oldchatUid);
        let user = null;

        if (userId) {
            user = await this.db.getUserById(userId);
        } else {
            // 尝试通过邮箱查找现有用户（如果有邮箱）
            if (oldchatUser.email) {
                user = await this.db.getUserByEmail(oldchatUser.email);
            }

            if (user) {
                // 存在邮箱相同的用户，建立 OldChat 关联
                await this.db.createOldChatUser(oldchatUid, user.id);
                // 可选更新用户信息（如头像、昵称等）
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

                // 生成用户名：优先使用 oldchatUser.username，若冲突则添加随机后缀
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

                // 建立 OldChat 关联
                await this.db.createOldChatUser(oldchatUid, user.id);
            }
        }

        // 3. 创建博客会话
        const token = await this.db.createSession(user.id);
        return { user, token };
    }
}