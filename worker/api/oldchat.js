import { Database } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class OldChatAuth {
    constructor(env) {
        this.apiBase = env.OLDCHAT_API_BASE || 'http://60.205.94.101:8080';
        this.db = new Database(env.BLOG_KV);
    }

    /**
     * 调用 OldChat 登录接口（带超时和完整字段）
     * @param {Object} payload - 前端发送的完整请求体（至少包含 identifier 和 password）
     * @returns {Promise<Object>} OldChat 返回的数据
     */
    async callOldChatLogin(payload) {
        const url = `${this.apiBase}/v1/auth/login`;
        // 构建完整请求体，补充必要字段
        const requestBody = {
            identifier: payload.identifier,
            password: payload.password,
            device_id: payload.device_id || 'blog-web',
            device_name: payload.device_name || 'NwelyBlog',
            platform: payload.platform || 'web',
            app_version: payload.app_version || '1.0.0'
        };

        // 使用 AbortController 实现超时（5秒）
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 5000);

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(requestBody),
                signal: controller.signal
            });
        } catch (err) {
            clearTimeout(timeout);
            if (err.name === 'AbortError') {
                console.error('OldChat 登录请求超时');
                throw new Error('OldChat 登录超时，请稍后重试');
            }
            console.error('OldChat 登录请求网络错误:', err);
            throw new Error('OldChat 服务器连接失败');
        }
        clearTimeout(timeout);

        // 读取原始响应文本，便于调试
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

        // 如果 HTTP 状态码不是 2xx，抛出错误
        if (!response.ok) {
            const errorMsg = data.error || data.message || `HTTP ${response.status}`;
            throw new Error(errorMsg);
        }

        return data; // 包含 access_token, refresh_token, user
    }

    /**
     * 处理 OldChat 登录：验证凭证，关联或创建本地用户，生成会话 token
     * @param {Object} payload - 前端发送的完整请求体
     * @returns {Promise<Object>} 包含本地用户和会话 token
     */
    async handleLogin(payload) {
        // 1. 调用 OldChat 登录
        const oldchatData = await this.callOldChatLogin(payload);
        const oldchatUser = oldchatData.user;
        const oldchatUid = oldchatUser.id || oldchatUser.uid; // 兼容两种字段名

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
                // 建立关联，并更新用户信息（头像等）
                await this.db.createOldChatUser(oldchatUid, user.id);
                // 可选更新用户信息（优先使用已有的，若没有则用 OldChat 的）
                const updates = {};
                if (!user.avatar && (oldchatUser.avatar_url || oldchatUser.avatar)) {
                    updates.avatar = oldchatUser.avatar_url || oldchatUser.avatar;
                }
                if (!user.bio && oldchatUser.signature) {
                    updates.bio = oldchatUser.signature;
                }
                if (Object.keys(updates).length > 0) {
                    await this.db.updateUser(user.id, updates);
                }
            } else {
                // 创建新用户
                const randomPassword = crypto.randomUUID();
                const hashedPassword = await bcrypt.hash(randomPassword, 10);

                // 生成用户名：优先使用 display_name 或 username，若冲突则添加随机后缀
                let username = oldchatUser.display_name || oldchatUser.username || `oldchat_${oldchatUid.slice(0, 8)}`;
                let existingUser = await this.db.getUserByUsername(username);
                if (existingUser) {
                    username = `${username}_${Math.random().toString(36).substring(2, 6)}`;
                }

                // 邮箱处理：如果没有邮箱，生成一个占位邮箱
                let email = oldchatUser.email;
                if (!email) {
                    email = `${oldchatUid}@oldchat.local`;
                    // 确保邮箱唯一
                    let suffix = 1;
                    while (await this.db.getUserByEmail(email)) {
                        email = `${oldchatUid}+${suffix}@oldchat.local`;
                        suffix++;
                    }
                }

                user = await this.db.createUser({
                    username,
                    email,
                    password: hashedPassword,
                    role: 'user',
                    avatar: oldchatUser.avatar_url || oldchatUser.avatar || null,
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