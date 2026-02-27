import { Database } from '../utils/db.js';

// 验证用户是否登录
export async function requireAuth(request, env) {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader) {
        throw new Error('请先登录');
    }

    const token = authHeader.replace('Bearer ', '');
    const db = new Database(env.BLOG_KV);
    const session = await db.getSession(token);

    if (!session) {
        throw new Error('登录已过期，请重新登录');
    }

    const user = await db.getUserById(session.userId);
    if (!user || !user.isActive) {
        throw new Error('用户不存在或已被禁用');
    }

    return { user, token };
}

// 验证管理员权限
export async function requireAdmin(request, env) {
    const { user } = await requireAuth(request, env);
    
    if (user.role === 'user') {
        throw new Error('需要管理员权限');
    }

    return { user };
}

// 验证超级管理员权限
export async function requireSuperAdmin(request, env) {
    const { user } = await requireAuth(request, env);
    
    if (user.role !== 'super_admin') {
        throw new Error('需要超级管理员权限');
    }

    return { user };
}

// 验证资源所有权（用户只能操作自己的资源）
export async function requireOwnership(request, env, resourceUserId) {
    const { user } = await requireAuth(request, env);
    
    if (user.id !== resourceUserId && user.role === 'user') {
        throw new Error('没有权限操作此资源');
    }

    return { user };
}