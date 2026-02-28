import { Database, ROLES } from '../utils/db.js';
import bcrypt from 'bcryptjs';

export class UsersAPI {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
    }

    // 获取用户列表（管理员）
    async getUsers(page = 1, limit = 20) {
        const users = await this.db.getAllUsers();
        const start = (page - 1) * limit;
        const end = start + limit;
        
        // 移除密码字段
        const safeUsers = users.map(({ password, ...user }) => user);
        
        return {
            users: safeUsers.slice(start, end),
            total: users.length,
            page,
            totalPages: Math.ceil(users.length / limit)
        };
    }

    // 获取单个用户
    async getUser(id) {
        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');
        
        // 移除密码字段
        const { password, ...safeUser } = user;
        return safeUser;
    }

    // 更新用户信息
    async updateUser(id, data, operatorId) {
        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');

        const operator = await this.db.getUserById(operatorId);
        
        // 普通用户只能更新自己的基本信息
        if (operatorId !== id && operator.role === 'user') {
            throw new Error('没有权限修改其他用户信息');
        }

        // 管理员不能修改超级管理员
        if (operator.role === 'admin' && user.role === 'super_admin') {
            throw new Error('不能修改超级管理员');
        }

        // 只有超级管理员可以修改角色
        if (data.role && operator.role !== 'super_admin') {
            throw new Error('没有权限修改用户角色');
        }

        // 如果要修改密码
        if (data.password) {
            data.password = await bcrypt.hash(data.password, 10);
        }

        const updated = await this.db.updateUser(id, data);
        
        // 移除密码字段
        const { password, ...safeUser } = updated;
        return safeUser;
    }
    // 修改密码
async changePassword(userId, oldPassword, newPassword) {
    const user = await this.db.getUserById(userId);
    if (!user) throw new Error('用户不存在');

    // 验证原密码
    const isValid = await bcrypt.compare(oldPassword, user.password);
    if (!isValid) throw new Error('原密码错误');

    // 加密新密码
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await this.db.updateUser(userId, { password: hashedPassword });

    return { success: true };
}
    // 更新当前用户个人资料（不需要管理员权限）
async updateProfile(userId, data) {
    const user = await this.db.getUserById(userId);
    if (!user) throw new Error('用户不存在');

    // 如果尝试修改用户名，检查唯一性
    if (data.username && data.username !== user.username) {
        const existingUser = await this.db.getUserByUsername(data.username);
        if (existingUser) throw new Error('用户名已被占用');
    }

    // 限制头像大小（base64 大致估算）
    if (data.avatar && data.avatar.length > 2 * 1024 * 1024) { // 2MB
        throw new Error('头像文件过大，请压缩后重试');
    }

    const updates = {};
    if (data.username) updates.username = data.username;
    if (data.bio !== undefined) updates.bio = data.bio;
    if (data.avatar !== undefined) updates.avatar = data.avatar; // 允许 null 恢复默认

    const updatedUser = await this.db.updateUser(userId, updates);
    // 移除密码字段
    const { password, ...safeUser } = updatedUser;
    return safeUser;
}

    // 删除用户（管理员）
    async deleteUser(id, operatorId) {
        if (id === operatorId) {
            throw new Error('不能删除自己的账号');
        }

        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');

        const operator = await this.db.getUserById(operatorId);
        
        // 超级管理员才能删除
        if (operator.role !== 'super_admin') {
            throw new Error('只有超级管理员可以删除用户');
        }

        // 不能删除超级管理员
        if (user.role === 'super_admin') {
            throw new Error('不能删除超级管理员');
        }

        // 删除用户的所有文章和评论
        const posts = await this.db.getPostsByAuthor(id);
        for (const post of posts) {
            await this.db.deletePost(post.id);
        }

        // 删除用户
        await this.db.kv.delete(`user:${id}`);
        await this.db.kv.delete(`user_email:${user.email}`);
        await this.db.kv.delete(`user_username:${user.username}`);
        
        // 从用户列表中移除
        const userList = await this.db.getUserList();
        const updatedList = userList.filter(uid => uid !== id);
        await this.db.kv.put('all_users', JSON.stringify(updatedList));

        return { success: true };
    }

    // 更改用户状态（启用/禁用）
    async toggleUserStatus(id, operatorId) {
        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');

        const operator = await this.db.getUserById(operatorId);
        
        if (operator.role === 'user') {
            throw new Error('没有权限');
        }

        if (operator.role === 'admin' && user.role === 'super_admin') {
            throw new Error('不能修改超级管理员状态');
        }

        const updated = await this.db.updateUser(id, {
            isActive: !user.isActive
        });

        const { password, ...safeUser } = updated;
        return safeUser;
    }

    // 更改用户角色（超级管理员）
    async changeUserRole(id, newRole, operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role !== 'super_admin') {
            throw new Error('只有超级管理员可以修改角色');
        }

        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');

        if (!Object.values(ROLES).includes(newRole)) {
            throw new Error('无效的角色');
        }

        const updated = await this.db.updateUser(id, { role: newRole });
        
        const { password, ...safeUser } = updated;
        return safeUser;
    }

    // 获取用户统计
    async getUserStats(id) {
        const user = await this.db.getUserById(id);
        if (!user) throw new Error('用户不存在');

        const posts = await this.db.getPostsByAuthor(id);
        const totalViews = posts.reduce((sum, post) => sum + (post.views || 0), 0);
        
        return {
            totalPosts: posts.length,
            publishedPosts: posts.filter(p => p.status === 'published').length,
            draftPosts: posts.filter(p => p.status === 'draft').length,
            totalViews,
            joinDate: user.createdAt,
            lastLogin: user.lastLogin
        };
    }
}