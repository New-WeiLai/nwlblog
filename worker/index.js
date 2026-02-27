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
router.options('*', () => new Response(null, { headers: corsHeaders }));

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

// ==================== 你之前的路由（文章、用户、评论、设置、统计）放在这里 ====================
// 将你提供的路由代码块粘贴在此处，确保所有路由都定义在 router 上
// 文章相关路由
router.get('/api/posts', async (request, env) => {
    try {
        const url = new URL(request.url);
        const page = parseInt(url.searchParams.get('page') || '1');
        const limit = parseInt(url.searchParams.get('limit') || '10');
        
        const postsAPI = new PostsAPI(env);
        const result = await postsAPI.getPosts(page, limit);
        
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

// 用户管理路由（管理员）
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

// 评论管理路由
router.get('/api/posts/:postId/comments', async (request, env) => {
    try {
        const postId = request.params.postId;
        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.getPostComments(postId);
        
        return new Response(JSON.stringify({ success: true, data: result }), {
            headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    } catch (error) {
        return new Response(JSON.stringify({ success: false, error: error.message }), {
            status: 400, headers: { 'Content-Type': 'application/json', ...corsHeaders }
        });
    }
});

router.post('/api/posts/:postId/comments', async (request, env) => {
    try {
        const { user } = await requireAuth(request, env);
        const postId = request.params.postId;
        const { content } = await request.json();
        
        const commentsAPI = new CommentsAPI(env);
        const result = await commentsAPI.createComment({ postId, content }, user.id);
        
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

// 设置路由
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

// 统计路由
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

// ==================== 404 处理 ====================
router.all('*', () => new Response('Not Found', { status: 404 }));

// ==================== 默认导出（事件处理器）====================
export default {
    async fetch(request, env, ctx) {
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