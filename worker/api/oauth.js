import { Database } from '../utils/db.js';
import { ROLES } from '../utils/db.js';

export class OAuthServer {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
        this.kv = env.BLOG_KV;
    }

    // 注册客户端（仅管理员调用）
    async registerClient(name, redirectUri) {
        const clientId = this.generateId('client');
        const clientSecret = this.generateSecret();
        const client = {
            client_id: clientId,
            client_secret: clientSecret,
            name,
            redirect_uri: redirectUri,
            scope: 'profile email', // 默认权限
            created_at: new Date().toISOString()
        };
        await this.kv.put(`oauth_client:${clientId}`, JSON.stringify(client));
        return { client_id: clientId, client_secret: clientSecret };
    }

    // 验证客户端
    async validateClient(clientId, redirectUri) {
        const clientJson = await this.kv.get(`oauth_client:${clientId}`);
        if (!clientJson) throw new Error('无效的 client_id');
        const client = JSON.parse(clientJson);
        if (client.redirect_uri !== redirectUri) {
            throw new Error('redirect_uri 不匹配');
        }
        return client;
    }

    // 生成授权码
    async generateAuthorizationCode(clientId, userId, redirectUri, scope) {
        const code = this.generateId('code');
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10分钟
        const authCode = {
            code,
            client_id: clientId,
            user_id: userId,
            redirect_uri: redirectUri,
            scope,
            expires_at: expiresAt.toISOString(),
            used: false
        };
        await this.kv.put(`oauth_code:${code}`, JSON.stringify(authCode), {
            expirationTtl: 10 * 60
        });
        return code;
    }

    // 用授权码换取令牌
    async exchangeCodeForToken(clientId, clientSecret, code, redirectUri) {
        // 验证客户端
        const clientJson = await this.kv.get(`oauth_client:${clientId}`);
        if (!clientJson) throw new Error('无效的 client_id');
        const client = JSON.parse(clientJson);
        if (client.client_secret !== clientSecret) {
            throw new Error('client_secret 无效');
        }

        // 验证授权码
        const codeJson = await this.kv.get(`oauth_code:${code}`);
        if (!codeJson) throw new Error('无效的授权码');
        const authCode = JSON.parse(codeJson);
        if (authCode.used) throw new Error('授权码已使用');
        if (authCode.client_id !== clientId) throw new Error('client_id 不匹配');
        if (authCode.redirect_uri !== redirectUri) throw new Error('redirect_uri 不匹配');
        if (new Date(authCode.expires_at) < new Date()) throw new Error('授权码已过期');

        // 标记为已使用
        authCode.used = true;
        await this.kv.put(`oauth_code:${code}`, JSON.stringify(authCode));

        // 生成访问令牌
        const token = this.generateId('token');
        const expiresIn = 7200; // 2小时
        const expiresAt = new Date(Date.now() + expiresIn * 1000);
        const accessToken = {
            token,
            client_id: clientId,
            user_id: authCode.user_id,
            scope: authCode.scope || client.scope,
            expires_at: expiresAt.toISOString(),
            created_at: new Date().toISOString()
        };
        await this.kv.put(`oauth_token:${token}`, JSON.stringify(accessToken), {
            expirationTtl: expiresIn
        });

        return {
            token,
            expires_in: expiresIn,
            scope: accessToken.scope
        };
    }

    // 通过令牌获取用户信息
    async getUserByToken(token) {
        const tokenJson = await this.kv.get(`oauth_token:${token}`);
        if (!tokenJson) throw new Error('无效的访问令牌');
        const accessToken = JSON.parse(tokenJson);
        if (new Date(accessToken.expires_at) < new Date()) {
            throw new Error('令牌已过期');
        }
        const user = await this.db.getUserById(accessToken.user_id);
        if (!user) throw new Error('用户不存在');
        return user;
    }

    // 生成随机 ID
    generateId(prefix) {
        return prefix + '_' + crypto.randomUUID().replace(/-/g, '');
    }

    // 生成客户端密钥（更长的随机串）
    generateSecret() {
        return crypto.randomUUID() + crypto.randomUUID().replace(/-/g, '');
    }
}