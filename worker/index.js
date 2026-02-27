// 在文件顶部添加导入
import { PostsAPI } from './api/posts.js';
import { UsersAPI } from './api/users.js';
import { CommentsAPI } from './api/comments.js';
import { SettingsAPI } from './api/settings.js';
import { requireAuth, requireAdmin, requireSuperAdmin } from './middleware/auth.js';

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