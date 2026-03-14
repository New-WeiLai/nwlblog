import showdown from 'showdown';
import { OldChatAuth } from './api/oldchat.js';
import { ColoryiAuth } from './api/coloryi.js';
import { Router } from 'itty-router';
import { AuthAPI } from './api/auth.js';
import { PostsAPI } from './api/posts.js';
import { UsersAPI } from './api/users.js';
import { CommentsAPI } from './api/comments.js';
import { SettingsAPI } from './api/settings.js';
import { requireAuth, requireAdmin, requireSuperAdmin } from './middleware/auth.js';
import { OAuthServer } from './api/oauth.js';

// CORS 头
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'true',
};

const router = Router();

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
        const payload = await request.json();
        if (!payload.identifier || !payload.password) {
            throw new Error('账号和密码不能为空');
        }
        const oldchat = new OldChatAuth(env);
        const result = await oldchat.handleLogin(payload);
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

// Coloryi 登录入口
router.get('/api/auth/coloryi', async (request, env) => {
    try {
        const state = crypto.randomUUID();
        const coloryi = new ColoryiAuth(env);
        const authUrl = coloryi.getAuthorizationUrl(state);
        return Response.redirect(authUrl, 302);
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// Coloryi 回调
router.get('/api/auth/coloryi/callback', async (request, env) => {
    try {
        const url = new URL(request.url);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        
        if (!code) throw new Error('未获取到授权码');
        
        const coloryi = new ColoryiAuth(env);
        const result = await coloryi.handleCallback(code, state);
        
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

// ==================== 文章路由（公开） ====================
router.get('/api/posts', async (request, env) => {
    try {
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '10');
        
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.getPosts(page, limit, false);
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
        const posts = await postsAPI.getPostsByAuthor(user.id);
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

// 发表评论（需登录）
router.post('/api/posts/:postId/comments', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const postId = request.params.postId;
        const { content } = await request.json();

        if (!content || content.trim() === '') {
            throw new Error('评论内容不能为空');
        }

        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.createComment({ postId, content }, user.id);

        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        const status = error.message.includes('未登录') ? 401 : 400;
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status,
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
        const result = await postsAPI.getPosts(page, limit, true);
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

// 获取单个用户（管理员）- 新增路由
router.get('/api/admin/users/:id', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const id = request.params.id;
        const usersAPI = new UsersAPI(env);
        const userData = await usersAPI.getUser(id);
        return new Response(JSON.stringify({ success: true, data: userData }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
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

// ==================== 新增的管理员路由（用于后台功能）====================
// 获取最新文章（用于仪表盘）
router.get('/api/admin/recent-posts', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const postsAPI = new PostsAPI(env);
        // 获取最近5篇已发布文章
        const result = await postsAPI.getPosts(1, 5, false);
        return new Response(JSON.stringify({ success: true, data: result.posts }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 获取最新评论（用于仪表盘）
router.get('/api/admin/recent-comments', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const commentsAPI = new CommentsAPI(env);
        // 获取最近5条评论（不限状态）
        const result = await commentsAPI.getComments(1, 5, 'all');
        return new Response(JSON.stringify({ success: true, data: result.comments }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 重置站点设置为默认值
router.post('/api/admin/settings/reset', async (request, env) => {
    try {
        const { user } = await requireSuperAdmin(request, env);
        const settingsAPI = new SettingsAPI(env);
        const result = await settingsAPI.resetSettings(user.id);
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

// 清除缓存（示例实现）
router.post('/api/admin/clear-cache', async (request, env) => {
    try {
        const { user } = await requireSuperAdmin(request, env);
        // 这里可以添加真正的缓存清理逻辑，例如删除某些 KV 前缀
        // 作为示例，仅返回成功
        return new Response(JSON.stringify({ success: true, message: '缓存已清除' }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 备份数据（示例实现）
router.get('/api/admin/backup', async (request, env) => {
    try {
        const { user } = await requireSuperAdmin(request, env);
        // 这里可以实现备份逻辑，例如获取所有用户、文章、评论等
        // 作为示例，返回一个简单的 JSON 对象
        const backup = {
            timestamp: new Date().toISOString(),
            message: '备份功能待实现'
        };
        return new Response(JSON.stringify(backup), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 401,
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

// 切换用户状态（启用/禁用）
router.post('/api/admin/users/:id/toggle-status', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
        const id = request.params.id;
        const usersAPI = new UsersAPI(env);
        const result = await usersAPI.toggleUserStatus(id, user.id);
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

// ==================== OAuth 2.0 ====================
// 客户端注册（仅管理员可调用，需认证）
router.post('/api/oauth/clients', async (request, env) => {
    try {
        const { user } = await requireAdmin(request, env);
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
        const responseType = url.searchParams.get('response_type');
        const scope = url.searchParams.get('scope') || '';
        const state = url.searchParams.get('state');

        if (responseType !== 'code') {
            throw new Error('仅支持 authorization_code 模式');
        }

        const oauth = new OAuthServer(env);
        await oauth.validateClient(clientId, redirectUri);

        const authHeader = request.headers.get('Authorization');
        let user = null;
        if (authHeader) {
            const token = authHeader.replace('Bearer ', '');
            const session = await oauth.db.getSession(token);
            if (session) user = await oauth.db.getUserById(session.userId);
        }

        if (!user) {
            const loginUrl = new URL('/login', env.SITE_URL);
            loginUrl.searchParams.set('redirect', request.url);
            return Response.redirect(loginUrl.toString(), 302);
        }

        const code = await oauth.generateAuthorizationCode(clientId, user.id, redirectUri, scope);
        const redirectUrl = new URL(redirectUri);
        redirectUrl.searchParams.set('code', code);
        if (state) redirectUrl.searchParams.set('state', state);
        return Response.redirect(redirectUrl.toString(), 302);
    } catch (error) {
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

router.get('/rss.xml', async (request, env) => {
    try {
        const postsAPI = new PostsAPI(env);
        const settingsAPI = new SettingsAPI(env);

        const settings = await settingsAPI.getPublicSettings();
        const siteTitle = settings.siteTitle || 'Nwely（陌筏）の 博客';
        const siteDescription = settings.siteDescription || '一个简洁美观的个人博客';
        const siteUrl = env.SITE_URL;

        const result = await postsAPI.getPosts(1, 20, false);
        const posts = result.posts;

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
            const contentHtml = markdownToHtml(post.content);
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

// 404 处理
router.all('*', () => new Response('Not Found', { status: 404 }));

// ==================== 默认导出 ====================
export default {
    async fetch(request, env, ctx) {
        // 处理所有 OPTIONS 预检请求
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