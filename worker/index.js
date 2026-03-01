import showdown from 'showdown';
import { OldChatAuth } from './api/oldchat.js';
import { Router } from 'itty-router';
import { AuthAPI } from './api/auth.js';
import { PostsAPI } from './api/posts.js';
import { UsersAPI } from './api/users.js';
import { CommentsAPI } from './api/comments.js';
import { SettingsAPI } from './api/settings.js';
import { requireAuth, requireAdmin, requireSuperAdmin } from './middleware/auth.js';

// CORS 头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
};

const router = Router();

// 处理 OPTIONS 预检请求
router.options('*', () => {
    return new Response(null, {
       /* headers: {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Credentials': 'true',
        }*/
    });
});

// 健康检查
router.get('/api/health', () => new Response(JSON.stringify({
    status: 'ok', timestamp: new Date().toISOString()
}), { headers: { 'Content-Type': 'application/json', ...corsHeaders } }));

// ==================== 认证路由 ====================
router.post('/api/auth/register', async (request, env) => {
    try {
        const { username, email, password, code } = await request.json();
        const auth = new AuthAPI(env);
        const result = await auth.register(username, email, password, code);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.post('/api/auth/login', async (request, env) => {
    try {
        const { email, password } = await request.json();
        const auth = new AuthAPI(env);
        const result = await auth.login(email, password);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.post('/api/auth/send-code', async (request, env) => {
    try {
        const { email, type } = await request.json();
        const auth = new AuthAPI(env);
        const result = await auth.sendVerificationCode(email, type || 'register');
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.post('/api/auth/verify-code', async (request, env) => {
    try {
        const { email, code, type } = await request.json();
        const auth = new AuthAPI(env);
        const result = await auth.verifyCode(email, code, type || 'register');
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.get('/api/auth/github', async (request, env) => {
    try {
        const state = crypto.randomUUID();
        const auth = new AuthAPI(env);
        const authUrl = auth.getGitHubAuthUrl(state);
        return Response.redirect(authUrl, 302);
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 500, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.get('/api/auth/github/callback', async (request, env) => {
    try {
        const url = new URL(request.url);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        
        if (!code) throw new Error('未获取到授权码');
        
        const auth = new AuthAPI(env);
        const result = await auth.handleGitHubCallback(code, state);
        
        const redirectUrl = new URL('/login', env.SITE_URL);
        redirectUrl.searchParams.set('token', result.token);
        redirectUrl.searchParams.set('success', 'true');
        
        return Response.redirect(redirectUrl.toString(), 302);
    } catch (error) {
        const redirectUrl = new URL('/login', env.SITE_URL);
        redirectUrl.searchParams.set('error', error.message);
        return Response.redirect(redirectUrl.toString(), 302);
    }
});

router.post('/api/auth/logout', async (request, env) => {
    try {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader?.replace('Bearer ', '');
        if (!token) throw new Error('未提供令牌');
        
        const auth = new AuthAPI(env);
        const result = await auth.logout(token);
        
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.get('/api/auth/me', async (request, env) => {
    try {
        const authHeader = request.headers.get('Authorization');
        const token = authHeader?.replace('Bearer ', '');
        if (!token) throw new Error('未提供令牌');
        
        const auth = new AuthAPI(env);
        const user = await auth.getCurrentUser(token);
        
        return new Response(JSON.stringify({ success: true, data: { user } }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// 用户个人资料更新（需登录）
router.put('/api/user/profile', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const data = await request.json();
        const usersAPI = new UsersAPI(env);
        const updatedUser = await usersAPI.updateProfile(user.id, data);
        return new Response(JSON.stringify({ success: true, data: { user: updatedUser } }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// 修改密码（需登录）
router.put('/api/user/password', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const { oldPassword, newPassword } = await request.json();
        const usersAPI = new UsersAPI(env);
        await usersAPI.changePassword(user.id, oldPassword, newPassword);
        return new Response(JSON.stringify({ success: true }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// OldChat 登录
router.post('/api/auth/oldchat/login', async (request, env) => {
    try {
        const { identifier, password, device_id } = await request.json();
        if (!identifier || !password) {
            throw new Error('账号和密码不能为空');
        }
        const oldchat = new OldChatAuth(env);
        const result = await oldchat.handleLogin(identifier, password, device_id || 'blog-web');
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// ==================== 文章路由（公开） ====================
router.get('/api/posts', async (request, env) => {
    try {
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '10');
        
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.getPosts(page, limit, false); // 只返回已发布文章
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.get('/api/posts/:id', async (request, env) => {
    try {
        const id = request.params.id;
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.getPost(id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 需要登录的文章操作
router.post('/api/posts', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const data = await request.json();
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.createPost(data, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.put('/api/posts/:id', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const id = request.params.id;
        const data = await request.json();
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.updatePost(id, data, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.delete('/api/posts/:id', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const id = request.params.id;
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.deletePost(id, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// 获取当前登录用户的所有文章（包含草稿）
router.get('/api/user/posts', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const postsAPI = new PostsAPI(env);
        const posts = await postsAPI.getPostsByAuthor(user.id); // 需要实现此方法
        return new Response(JSON.stringify({ success: true, data: { posts } }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// 为评论路由添加 OPTIONS 预检处理
router.options('/api/posts/:postId/comments', () => {
    return new Response(null, { headers: corsHeaders });
});

// ==================== 管理员路由 ====================
// 文章管理（管理员）
router.get('/api/admin/posts', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '10');
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.getPosts(page, limit, true); // true 表示包含草稿
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 用户管理（管理员）
router.get('/api/admin/users', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '20');
        
        const usersAPI = new UsersAPI(env);
        const result = await usersAPI.getUsers(page, limit);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.put('/api/admin/users/:id', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const id = request.params.id;
        const data = await request.json();
        
        const usersAPI = new UsersAPI(env);
        const result = await usersAPI.updateUser(id, data, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.delete('/api/admin/users/:id', async (request, env) => {
    try {
        const { user } = await requireSuperAdmin(request, env);
        const id = request.params.id;
        
        const usersAPI = new UsersAPI(env);
        const result = await usersAPI.deleteUser(id, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 评论管理（管理员）
router.get('/api/admin/comments', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '20');
        const status = url.searchParams.get('status') || 'all';
        const postId = url.searchParams.get('postId');
        
        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.getComments(page, limit, status, postId);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.put('/api/admin/comments/:id', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const id = request.params.id;
        const { status } = await request.json();
        
        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.updateCommentStatus(id, status, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.delete('/api/admin/comments/:id', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const id = request.params.id;
        
        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.deleteComment(id, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 站点设置（管理员）
router.get('/api/admin/settings', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const settingsAPI = new SettingsAPI(env);
        const result = await settingsAPI.getAllSettings(user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.put('/api/admin/settings', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const settings = await request.json();
        const settingsAPI = new SettingsAPI(env);
        const result = await settingsAPI.updateSettings(settings, user.id);
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 统计（管理员）
router.get('/api/admin/stats', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const settingsAPI = new SettingsAPI(env);
        const stats = await settingsAPI.getSiteStats();
        return new Response(JSON.stringify({ success: true, data: stats }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// ==================== 公共设置路由（无需登录）====================
router.get('/api/settings', async (request, env) => {
    try {
        const settingsAPI = new SettingsAPI(env);
        const result = await settingsAPI.getPublicSettings();
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// 导入 OAuth 处理模块
import { OAuthServer } from './api/oauth.js';

// 客户端注册（仅管理员可调用，需认证）
router.post('/api/oauth/clients', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env); // 只有管理员能注册第三方应用
        const { name, redirect_uri } = await request.json();
        const oauth = new OAuthServer(env);
        const client = await oauth.registerClient(name, redirect_uri);
        return new Response(JSON.stringify({ success: true, data: client }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 授权端点
router.get('/oauth/authorize', async (request, env) => {
    try {
        const url = new URL(request.url);
        const clientId = url.searchParams.get('client_id');
        const redirectUri = url.searchParams.get('redirect_uri');
        const responseType = url.searchParams.get('response_type'); // 应为 'code'
        const scope = url.searchParams.get('scope') || '';
        const state = url.searchParams.get('state');

        if (responseType !== 'code') {
            throw new Error('仅支持 authorization_code 模式');
        }

        const oauth = new OAuthServer(env);
        // 验证客户端
        await oauth.validateClient(clientId, redirectUri);

        // 此处应检查用户是否已登录，若未登录则跳转到登录页
        const authHeader = request.headers.get('Authorization');
        let user = null;
        if (authHeader) {
            const token = authHeader.replace('Bearer ', '');
            const session = await oauth.db.getSession(token);
            if (session) user = await oauth.db.getUserById(session.userId);
        }

        if (!user) {
            // 保存当前请求参数到 session 或 cookie，登录后跳回
            const loginUrl = new URL('/login', env.SITE_URL);
            loginUrl.searchParams.set('redirect', request.url);
            return Response.redirect(loginUrl.toString(), 302);
        }

        // 显示授权页面（简化：直接生成 code 并重定向，跳过用户确认）
        const code = await oauth.generateAuthorizationCode(clientId, user.id, redirectUri, scope);
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (state) redirectUrl.searchParams.set('state', state);
        return Response.redirect(redirectUrl.toString(), 302);
    } catch (error) {
        // 错误处理：跳转到 redirect_uri 并携带 error 参数
        const url = new URL(request.url);
        const redirectUri = url.searchParams.get('redirect_uri') || env.SITE_URL;
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('error', error.message);
        return Response.redirect(redirectUrl.toString(), 302);
    }
});

// 令牌端点
router.post('/oauth/token', async (request, env) => {
    try {
        const formData = await request.formData();
        const grantType = formData.get('grant_type');
        const code = formData.get('code');
        const redirectUri = formData.get('redirect_uri');
        const clientId = formData.get('client_id');
        const clientSecret = formData.get('client_secret');

        if (grantType !== 'authorization_code') {
            throw new Error('不支持的 grant_type');
        }

        const oauth = new OAuthServer(env);
        const tokenData = await oauth.exchangeCodeForToken(clientId, clientSecret, code, redirectUri);
        return new Response(JSON.stringify({
            access_token: tokenData.token,
            token_type: 'Bearer',
            expires_in: tokenData.expires_in,
            scope: tokenData.scope
        }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 400,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 用户信息端点
router.get('/oauth/userinfo', async (request, env) => {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            throw new Error('缺少访问令牌');
        }
        const token = authHeader.substring(7);
        const oauth = new OAuthServer(env);
        const user = await oauth.getUserByToken(token);
        return new Response(JSON.stringify({
            sub: user.id,
            name: user.username,
            email: user.email,
            picture: user.avatar
        }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});
// ==================== RSS 订阅源 ====================
router.get('/rss.xml', async (request, env) => {
    try {
        const postsAPI = new PostsAPI(env);
        const settingsAPI = new SettingsAPI(env);

        // 获取博客设置
        const settings = await settingsAPI.getPublicSettings();
        const siteTitle = settings.siteTitle || 'Nwely（陌筏）の 博客';
        const siteDescription = settings.siteDescription || '一个简洁美观的个人博客';
        const siteUrl = env.SITE_URL; // 例如 https://blog.nwely.top

        // 获取最近 20 篇已发布的文章
        const result = await postsAPI.getPosts(1, 20, false); // 只返回已发布
        const posts = result.posts;

        // 构建 RSS XML
        const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <channel>
        <title>${escapeXml(siteTitle)}</title>
        <link>${siteUrl}</link>
        <description>${escapeXml(siteDescription)}</description>
        <language>zh-cn</language>
        <atom:link href="${siteUrl}/rss.xml" rel="self" type="application/rss+xml" />
        <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
        ${posts.map(post => `
        <item>
            <title>${escapeXml(post.title)}</title>
            <link>${siteUrl}/post.html?id=${post.id}</link>
            <guid isPermaLink="false">${siteUrl}/post.html?id=${post.id}</guid>
            <pubDate>${new Date(post.publishedAt || post.createdAt).toUTCString()}</pubDate>
            <description><![CDATA[${post.content}]]></description>
        </item>
        `).join('')}
    </channel>
</rss>`;

        return new Response(rss, {
            headers: {
                'Content-Type': 'application/rss+xml; charset=utf-8',
                'Cache-Control': 'max-age=3600', // 缓存1小时
            }
        });
    } catch (error) {
        console.error('生成 RSS 失败:', error);
        return new Response('生成 RSS 失败', { status: 500 });
    }
});

// ==================== RSS 订阅源 ====================
// 引入 showdown（如果你已经在其他地方使用，可以直接复用；如果没有，需要添加）
// 注意：如果你没有在 Worker 中使用 showdown，你需要导入它。
// 由于 Worker 环境支持 ES Module，我们可以动态导入或者提前安装。
// 为简化，我们假设你在代码中已经使用 showdown，否则需要先安装。

// 如果还没有 showdown，请运行: npm install showdown
// 并在文件顶部导入: import showdown from 'showdown';

// 为了确保能运行，我们使用之前已经导入的 converter（如果之前已经创建）
// 如果你之前没有创建，可以在这里创建：
// const converter = new showdown.Converter({ simpleLineBreaks: true, ghCompatibleHeaderId: true });

// 假设之前已经创建了 converter 对象，如果没有，需要创建。

// 为了兼容你的项目结构，我们假设没有全局 converter，所以这里动态创建：
function markdownToHtml(md) {
    if (!md) return '';
    const converter = new showdown.Converter({
        simplifiedAutoLink: true,
        excludeTrailingPunctuationFromURLs: true,
        strikethrough: true,
        tables: true,
        tasklists: true,
        openLinksInNewWindow: true,
        emoji: true,
        ghCodeBlocks: true,
        ghMentions: true,
        ghMentionsLink: 'https://github.com/{u}',
        simpleLineBreaks: true
    });
    return converter.makeHtml(md);
}

router.get('/rss.xml', async (request, env) => {
    try {
        const postsAPI = new PostsAPI(env);
        const settingsAPI = new SettingsAPI(env);

        const settings = await settingsAPI.getPublicSettings();
        const siteTitle = settings.siteTitle || 'Nwely（陌筏）の 博客';
        const siteDescription = settings.siteDescription || '一个简洁美观的个人博客';
        const siteUrl = env.SITE_URL; // 例如 https://blog.nwely.top

        // 获取最近 20 篇已发布的文章
        const result = await postsAPI.getPosts(1, 20, false);
        const posts = result.posts;

        // 构建 RSS XML
        const rss = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <channel>
        <title>${escapeXml(siteTitle)}</title>
        <link>${siteUrl}</link>
        <description>${escapeXml(siteDescription)}</description>
        <language>zh-cn</language>
        <atom:link href="${siteUrl}/rss.xml" rel="self" type="application/rss+xml" />
        <lastBuildDate>${new Date().toUTCString()}</lastBuildDate>
        ${posts.map(post => {
            // 将 Markdown 转换为 HTML
            const contentHtml = markdownToHtml(post.content);
            // 可选：生成纯文本摘要
            const plainText = stripMarkdown(post.content);
            const summary = plainText.length > 500 ? plainText.substring(0, 500) + '…' : plainText;
            return `
        <item>
            <title>${escapeXml(post.title)}</title>
            <link>${siteUrl}/post.html?id=${post.id}</link>
            <guid isPermaLink="false">${siteUrl}/post.html?id=${post.id}</guid>
            <pubDate>${new Date(post.publishedAt || post.createdAt).toUTCString()}</pubDate>
            <description><![CDATA[${contentHtml}]]></description>
        </item>`;
        }).join('')}
    </channel>
</rss>`;

        return new Response(rss, {
            headers: {
                'Content-Type': 'application/rss+xml; charset=utf-8',
                'Cache-Control': 'max-age=3600',
            }
        });
    } catch (error) {
        console.error('生成 RSS 失败:', error);
        return new Response('生成 RSS 失败', { status: 500 });
    }
});

// 简单的 Markdown 转纯文本函数（用于摘要，可选）
function stripMarkdown(md) {
    if (!md) return '';
    return md
        .replace(/^#+\s*/gm, '')
        .replace(/(\*\*|__)(.*?)\1/g, '$2')
        .replace(/(\*|_)(.*?)\1/g, '$2')
        .replace(/\[([^\]]+)\]\([^\)]+\)/g, '$1')
        .replace(/!\[([^\]]*)\]\([^\)]+\)/g, '$1')
        .replace(/```[\s\S]*?```/g, '')
        .replace(/`([^`]+)`/g, '$1')
        .replace(/\n{3,}/g, '\n\n');
}

function escapeXml(unsafe) {
    if (!unsafe) return '';
    return unsafe.replace(/[<>&'"]/g, (c) => {
        switch (c) {
            case '<': return '&lt;';
            case '>': return '&gt;';
            case '&': return '&amp;';
            case '\'': return '&apos;';
            case '"': return '&quot;';
            default: return c;
        }
    });
}
// 404 处理
router.all('*', () => new Response('Not Found', { status: 404 }));

// ==================== 默认导出（事件处理器）====================
export default {
    async fetch(request, env, ctx) {
        // 处理所有 OPTIONS 预检请求，直接返回 CORS 头
        if (request.method === 'OPTIONS') {
            return new Response(null, {
                headers: {
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                    'Access-Control-Allow-Credentials': 'true',
                }
            });
        }

        try {
            return await router.handle(request, env, ctx);
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: error.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json', ...corsHeaders }
            });
        }
    }
};