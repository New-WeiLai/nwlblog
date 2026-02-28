import { Database } from '../utils/db.js';

export class PostsAPI {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
    }

    // 获取文章列表
    async getPosts(page = 1, limit = 10, includeDrafts = false) {
        const posts = await this.db.getAllPosts(includeDrafts);
        const start = (page - 1) * limit;
        const end = start + limit;
        
        return {
            posts: posts.slice(start, end),
            total: posts.length,
            page,
            totalPages: Math.ceil(posts.length / limit)
        };
    }

    // 获取单篇文章
    async getPost(id) {
        const post = await this.db.getPostById(id);
        if (!post) throw new Error('文章不存在');
        
        // 增加阅读量
        await this.db.updatePost(id, { views: post.views + 1 });
        
        // 获取评论
        const comments = await this.db.getCommentsByPost(id);
        
        return { ...post, comments };
    }

    // 创建文章
    async createPost(data, userId) {
        const user = await this.db.getUserById(userId);
        if (!user) throw new Error('用户不存在');

        const post = await this.db.createPost({
            ...data,
            authorId: userId,
            authorName: user.username
        });

        return post;
    }

    // 更新文章
    async updatePost(id, data, userId) {
        const post = await this.db.getPostById(id);
        if (!post) throw new Error('文章不存在');

        // 检查权限（作者或管理员）
        const user = await this.db.getUserById(userId);
        if (post.authorId !== userId && user.role === 'user') {
            throw new Error('没有权限修改此文章');
        }

        const updated = await this.db.updatePost(id, data);
        return updated;
    }

    // 删除文章
    async deletePost(id, userId) {
        const post = await this.db.getPostById(id);
        if (!post) throw new Error('文章不存在');

        // 检查权限（作者或管理员）
        const user = await this.db.getUserById(userId);
        if (post.authorId !== userId && user.role === 'user') {
            throw new Error('没有权限删除此文章');
        }

        await this.db.deletePost(id);
        return { success: true };
    }

    // 搜索文章
    async searchPosts(keyword) {
        const posts = await this.db.getAllPosts();
        const results = posts.filter(post => 
            post.title.toLowerCase().includes(keyword.toLowerCase()) ||
            post.content.toLowerCase().includes(keyword.toLowerCase())
        );
        return results;
    }

    // 获取作者的文章
    async getPostsByAuthor(authorId) {
        const posts = await this.db.getAllPosts();
        return posts.filter(post => post.authorId === authorId);
    }
    // 在 PostsAPI 类中
    async getPostsByAuthor(authorId) {
        const allPosts = await this.db.getAllPosts(true); // 获取所有文章（含草稿）
        return allPosts.filter(post => post.authorId === authorId);
    }
}
