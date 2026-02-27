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
}