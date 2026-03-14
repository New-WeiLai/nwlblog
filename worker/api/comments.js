import { Database } from '../utils/db.js';

export class CommentsAPI {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
    }

    // 获取文章的评论
    async getPostComments(postId, includeUnapproved = false) {
        const comments = await this.db.getCommentsByPost(postId, includeUnapproved);
        return comments;
    }

    // 创建评论
    async createComment(data, userId) {
        const user = await this.db.getUserById(userId);
        if (!user) throw new Error('用户不存在');

        const settings = await this.db.getSettings();
        const status = settings.commentModeration ? 'pending' : 'approved';

        const comment = await this.db.createComment({
            ...data,
            authorId: userId,
            authorName: user.username,
            status
        });

        return comment;
    }

    // 更新评论状态（审核）
    async updateCommentStatus(commentId, status, operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role === 'user') {
            throw new Error('没有权限审核评论');
        }

        const comment = await this.db.updateCommentStatus(commentId, status);
        return comment;
    }

    // 删除评论
    async deleteComment(commentId, userId) {
        const comment = await this.db.kv.get(`comment:${commentId}`);
        if (!comment) throw new Error('评论不存在');

        const commentData = JSON.parse(comment);
        const user = await this.db.getUserById(userId);

        // 作者或管理员可以删除
        if (commentData.authorId !== userId && user.role === 'user') {
            throw new Error('没有权限删除此评论');
        }

        await this.db.kv.delete(`comment:${commentId}`);

        // 从文章的评论列表中移除
        const commentsKey = `comments_post:${commentData.postId}`;
        const existingComments = await this.db.kv.get(commentsKey);
        if (existingComments) {
            const commentList = JSON.parse(existingComments).filter(id => id !== commentId);
            await this.db.kv.put(commentsKey, JSON.stringify(commentList));
        }

        return { success: true };
    }

    // 获取待审核评论（管理员）
    async getPendingComments() {
        const posts = await this.db.getAllPosts();
        let pendingComments = [];

        for (const post of posts) {
            const comments = await this.db.getCommentsByPost(post.id, true);
            pendingComments = pendingComments.concat(
                comments.filter(c => c.status === 'pending')
            );
        }

        return pendingComments;
    }

    // ========== 新增：获取评论列表（管理员，支持分页和过滤） ==========
    async getComments(page = 1, limit = 20, status = 'all', postId = null) {
        let allComments = [];

        if (postId && postId !== 'all') {
            // 获取特定文章的评论
            allComments = await this.db.getCommentsByPost(postId, true);
        } else {
            // 获取所有文章的评论（遍历所有文章）
            const posts = await this.db.getAllPosts(true);
            for (const post of posts) {
                const comments = await this.db.getCommentsByPost(post.id, true);
                allComments = allComments.concat(comments);
            }
        }

        // 按状态过滤
        if (status !== 'all') {
            allComments = allComments.filter(c => c.status === status);
        }

        // 按时间排序（最新的在前）
        allComments.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

        // 分页
        const start = (page - 1) * limit;
        const end = start + limit;
        const paginatedComments = allComments.slice(start, end);

        return {
            comments: paginatedComments,
            total: allComments.length,
            page,
            totalPages: Math.ceil(allComments.length / limit)
        };
    }
}