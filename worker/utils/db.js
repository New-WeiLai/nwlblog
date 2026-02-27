const ROLES = {
    SUPER_ADMIN: 'super_admin',
    ADMIN: 'admin',
    USER: 'user'
};

const DEFAULT_SETTINGS = {
    siteTitle: 'Nwely（陌筏）の 博客',
    siteDescription: '一个简洁美观的个人博客',
    headerImage: '/avatar.png',
    backgroundImage: '',  // 背景图默认为空，可在后台设置
    footerText: '© {year} Nwely的博客. All rights reserved.',
    allowRegistration: true,
    requireEmailVerification: false,
    postsPerPage: 10,
    enableComments: true,
    commentModeration: true
};

const KEYS = {
    USER: (id) => `user:${id}`,
    USER_BY_EMAIL: (email) => `user_email:${email.toLowerCase()}`,
    USER_BY_USERNAME: (username) => `user_username:${username.toLowerCase()}`,
    SESSION: (token) => `session:${token}`,
    POST: (id) => `post:${id}`,
    POSTS_BY_AUTHOR: (authorId) => `posts_author:${authorId}`,
    COMMENTS_BY_POST: (postId) => `comments_post:${postId}`,
    COMMENT: (id) => `comment:${id}`,
    SETTINGS: 'site_settings',
    ALL_USERS: 'all_users',
    ALL_POSTS: 'all_posts',
    STATS: 'site_stats',
    EMAIL_VERIFICATION: (email) => `verify:${email.toLowerCase()}`,
    GITHUB_USER: (githubId) => `github:${githubId}`,
    RESET_PASSWORD: (email) => `reset:${email.toLowerCase()}`,
    EMAIL_ATTEMPTS: (email) => `attempts:${email.toLowerCase()}`
};

export class Database {
    constructor(kv) {
        this.kv = kv;
    }

    async createUser(userData) {
        const userId = crypto.randomUUID();
        const timestamp = new Date().toISOString();
        
        const user = {
            id: userId,
            username: userData.username,
            email: userData.email.toLowerCase(),
            password: userData.password,
            role: userData.role || ROLES.USER,
            createdAt: timestamp,
            updatedAt: timestamp,
            lastLogin: null,
            isActive: true,
            avatar: userData.avatar || null,
            bio: userData.bio || '',
            githubId: userData.githubId || null
        };

        const existingEmail = await this.kv.get(KEYS.USER_BY_EMAIL(user.email));
        const existingUsername = await this.kv.get(KEYS.USER_BY_USERNAME(user.username));
        
        if (existingEmail || existingUsername) {
            throw new Error('Email or username already exists');
        }

        await this.kv.put(KEYS.USER(userId), JSON.stringify(user));
        await this.kv.put(KEYS.USER_BY_EMAIL(user.email), userId);
        await this.kv.put(KEYS.USER_BY_USERNAME(user.username), userId);
        
        const userList = await this.getUserList();
        userList.push(userId);
        await this.kv.put(KEYS.ALL_USERS, JSON.stringify(userList));

        return user;
    }

    async getUserById(userId) {
        const user = await this.kv.get(KEYS.USER(userId));
        return user ? JSON.parse(user) : null;
    }

    async getUserByEmail(email) {
        const userId = await this.kv.get(KEYS.USER_BY_EMAIL(email.toLowerCase()));
        return userId ? this.getUserById(userId) : null;
    }

    async getUserByUsername(username) {
        const userId = await this.kv.get(KEYS.USER_BY_USERNAME(username.toLowerCase()));
        return userId ? this.getUserById(userId) : null;
    }

    async updateUser(userId, updates) {
        const user = await this.getUserById(userId);
        if (!user) throw new Error('User not found');

        const updatedUser = {
            ...user,
            ...updates,
            updatedAt: new Date().toISOString()
        };

        await this.kv.put(KEYS.USER(userId), JSON.stringify(updatedUser));
        return updatedUser;
    }

    async getUserList() {
        const list = await this.kv.get(KEYS.ALL_USERS);
        return list ? JSON.parse(list) : [];
    }

    async getAllUsers() {
        const userIds = await this.getUserList();
        const users = await Promise.all(
            userIds.map(id => this.getUserById(id))
        );
        return users.filter(u => u !== null);
    }

    async createSession(userId) {
        const token = crypto.randomUUID();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 7);

        const session = {
            userId,
            token,
            createdAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString()
        };

        await this.kv.put(KEYS.SESSION(token), JSON.stringify(session), {
            expirationTtl: 7 * 24 * 60 * 60
        });

        return token;
    }

    async getSession(token) {
        const session = await this.kv.get(KEYS.SESSION(token));
        return session ? JSON.parse(session) : null;
    }

    async deleteSession(token) {
        await this.kv.delete(KEYS.SESSION(token));
    }

    async createPost(postData) {
        const postId = crypto.randomUUID();
        const timestamp = new Date().toISOString();

        const post = {
            id: postId,
            title: postData.title,
            content: postData.content,
            excerpt: postData.excerpt || postData.content.substring(0, 200) + '...',
            authorId: postData.authorId,
            authorName: postData.authorName,
            status: postData.status || 'published',
            createdAt: timestamp,
            updatedAt: timestamp,
            publishedAt: postData.status === 'published' ? timestamp : null,
            tags: postData.tags || [],
            views: 0,
            likes: 0,
            featuredImage: postData.featuredImage || null
        };

        await this.kv.put(KEYS.POST(postId), JSON.stringify(post));

        const postList = await this.getPostList();
        postList.push(postId);
        await this.kv.put(KEYS.ALL_POSTS, JSON.stringify(postList));

        const authorPostsKey = KEYS.POSTS_BY_AUTHOR(postData.authorId);
        const authorPosts = await this.kv.get(authorPostsKey);
        const authorPostList = authorPosts ? JSON.parse(authorPosts) : [];
        authorPostList.push(postId);
        await this.kv.put(authorPostsKey, JSON.stringify(authorPostList));

        return post;
    }

    async getPostById(postId) {
        const post = await this.kv.get(KEYS.POST(postId));
        return post ? JSON.parse(post) : null;
    }

    async updatePost(postId, updates) {
        const post = await this.getPostById(postId);
        if (!post) throw new Error('Post not found');

        const updatedPost = {
            ...post,
            ...updates,
            updatedAt: new Date().toISOString()
        };

        await this.kv.put(KEYS.POST(postId), JSON.stringify(updatedPost));
        return updatedPost;
    }

    async deletePost(postId) {
        const post = await this.getPostById(postId);
        if (!post) return;

        await this.kv.delete(KEYS.POST(postId));

        const postList = await this.getPostList();
        const updatedList = postList.filter(id => id !== postId);
        await this.kv.put(KEYS.ALL_POSTS, JSON.stringify(updatedList));

        const authorPostsKey = KEYS.POSTS_BY_AUTHOR(post.authorId);
        const authorPosts = await this.kv.get(authorPostsKey);
        if (authorPosts) {
            const authorList = JSON.parse(authorPosts).filter(id => id !== postId);
            await this.kv.put(authorPostsKey, JSON.stringify(authorList));
        }

        const commentsKey = KEYS.COMMENTS_BY_POST(postId);
        const commentIds = await this.kv.get(commentsKey);
        if (commentIds) {
            const ids = JSON.parse(commentIds);
            await Promise.all(ids.map(id => this.kv.delete(KEYS.COMMENT(id))));
            await this.kv.delete(commentsKey);
        }
    }

    async getPostList() {
        const list = await this.kv.get(KEYS.ALL_POSTS);
        return list ? JSON.parse(list) : [];
    }

    async getAllPosts(includeDrafts = false) {
        const postIds = await this.getPostList();
        const posts = await Promise.all(
            postIds.map(id => this.getPostById(id))
        );
        
        let filtered = posts.filter(p => p !== null);
        if (!includeDrafts) {
            filtered = filtered.filter(p => p.status === 'published');
        }
        
        return filtered.sort((a, b) => 
            new Date(b.publishedAt || b.createdAt) - new Date(a.publishedAt || a.createdAt)
        );
    }

    async createComment(commentData) {
        const commentId = crypto.randomUUID();
        const timestamp = new Date().toISOString();

        const comment = {
            id: commentId,
            postId: commentData.postId,
            authorId: commentData.authorId,
            authorName: commentData.authorName,
            content: commentData.content,
            status: commentData.status || 'pending',
            createdAt: timestamp,
            updatedAt: timestamp,
            parentId: commentData.parentId || null
        };

        await this.kv.put(KEYS.COMMENT(commentId), JSON.stringify(comment));

        const commentsKey = KEYS.COMMENTS_BY_POST(commentData.postId);
        const existingComments = await this.kv.get(commentsKey);
        const commentList = existingComments ? JSON.parse(existingComments) : [];
        commentList.push(commentId);
        await this.kv.put(commentsKey, JSON.stringify(commentList));

        return comment;
    }

    async getCommentsByPost(postId, includeUnapproved = false) {
        const commentsKey = KEYS.COMMENTS_BY_POST(postId);
        const commentIds = await this.kv.get(commentsKey);
        
        if (!commentIds) return [];
        
        const ids = JSON.parse(commentIds);
        const comments = await Promise.all(
            ids.map(id => this.kv.get(KEYS.COMMENT(id)).then(c => c ? JSON.parse(c) : null))
        );
        
        let filtered = comments.filter(c => c !== null);
        if (!includeUnapproved) {
            filtered = filtered.filter(c => c.status === 'approved');
        }
        
        return filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    }

    async updateCommentStatus(commentId, status) {
        const comment = await this.kv.get(KEYS.COMMENT(commentId));
        if (!comment) throw new Error('Comment not found');

        const updatedComment = JSON.parse(comment);
        updatedComment.status = status;
        updatedComment.updatedAt = new Date().toISOString();

        await this.kv.put(KEYS.COMMENT(commentId), JSON.stringify(updatedComment));
        return updatedComment;
    }

    async getSettings() {
        const settings = await this.kv.get(KEYS.SETTINGS);
        return settings ? JSON.parse(settings) : DEFAULT_SETTINGS;
    }

    async updateSettings(newSettings) {
        const currentSettings = await this.getSettings();
        const updatedSettings = {
            ...currentSettings,
            ...newSettings,
            updatedAt: new Date().toISOString()
        };

        await this.kv.put(KEYS.SETTINGS, JSON.stringify(updatedSettings));
        return updatedSettings;
    }

    async createVerificationCode(email, type = 'register') {
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        const expiresAt = new Date();
        expiresAt.setMinutes(expiresAt.getMinutes() + 10);

        const verification = {
            code,
            email: email.toLowerCase(),
            type,
            attempts: 0,
            createdAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString(),
            verified: false
        };

        const attemptsKey = KEYS.EMAIL_ATTEMPTS(email);
        const attempts = await this.kv.get(attemptsKey);
        const attemptCount = attempts ? JSON.parse(attempts) : { count: 0, lastReset: new Date().toISOString() };
        
        const lastReset = new Date(attemptCount.lastReset);
        const now = new Date();
        if (now - lastReset > 24 * 60 * 60 * 1000) {
            attemptCount.count = 0;
            attemptCount.lastReset = now.toISOString();
        }
        
        if (attemptCount.count >= 5) {
            throw new Error('今日验证码发送次数已达上限');
        }
        
        attemptCount.count++;
        await this.kv.put(attemptsKey, JSON.stringify(attemptCount), {
            expirationTtl: 24 * 60 * 60
        });

        await this.kv.put(KEYS.EMAIL_VERIFICATION(email), JSON.stringify(verification), {
            expirationTtl: 10 * 60
        });

        return code;
    }

    async verifyCode(email, code, type = 'register') {
        const verificationKey = KEYS.EMAIL_VERIFICATION(email);
        const verification = await this.kv.get(verificationKey);
        
        if (!verification) {
            throw new Error('验证码不存在或已过期');
        }

        const data = JSON.parse(verification);
        
        if (data.type !== type) {
            throw new Error('验证码类型错误');
        }
        
        if (new Date(data.expiresAt) < new Date()) {
            await this.kv.delete(verificationKey);
            throw new Error('验证码已过期');
        }
        
        data.attempts++;
        if (data.attempts > 5) {
            await this.kv.delete(verificationKey);
            throw new Error('验证码尝试次数过多');
        }
        
        if (data.code !== code) {
            await this.kv.put(verificationKey, JSON.stringify(data), {
                expirationTtl: 10 * 60
            });
            throw new Error('验证码错误');
        }
        
        data.verified = true;
        await this.kv.put(verificationKey, JSON.stringify(data), {
            expirationTtl: 10 * 60
        });
        
        return true;
    }

    async isEmailVerified(email, type = 'register') {
        const verification = await this.kv.get(KEYS.EMAIL_VERIFICATION(email));
        if (!verification) return false;
        
        const data = JSON.parse(verification);
        return data.verified === true && data.type === type;
    }

    async clearVerification(email) {
        await this.kv.delete(KEYS.EMAIL_VERIFICATION(email));
    }

    async createGitHubUser(githubId, userId) {
        await this.kv.put(KEYS.GITHUB_USER(githubId), userId);
    }

    async getUserIdByGitHub(githubId) {
        return await this.kv.get(KEYS.GITHUB_USER(githubId));
    }

    async createPasswordResetToken(email) {
        const token = crypto.randomUUID();
        const expiresAt = new Date();
        expiresAt.setHours(expiresAt.getHours() + 1);

        const reset = {
            token,
            email: email.toLowerCase(),
            createdAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString(),
            used: false
        };

        await this.kv.put(KEYS.RESET_PASSWORD(email), JSON.stringify(reset), {
            expirationTtl: 60 * 60
        });

        return token;
    }

    async verifyPasswordResetToken(email, token) {
        const resetKey = KEYS.RESET_PASSWORD(email);
        const reset = await this.kv.get(resetKey);
        
        if (!reset) {
            throw new Error('重置链接已过期或无效');
        }

        const data = JSON.parse(reset);
        
        if (data.used) {
            throw new Error('该链接已被使用');
        }
        
        if (new Date(data.expiresAt) < new Date()) {
            await this.kv.delete(resetKey);
            throw new Error('重置链接已过期');
        }
        
        if (data.token !== token) {
            throw new Error('无效的令牌');
        }
        
        return true;
    }

    async markPasswordResetUsed(email) {
        const resetKey = KEYS.RESET_PASSWORD(email);
        const reset = await this.kv.get(resetKey);
        if (reset) {
            const data = JSON.parse(reset);
            data.used = true;
            await this.kv.put(resetKey, JSON.stringify(data), {
                expirationTtl: 60 * 60
            });
        }
    }
}

export { ROLES, DEFAULT_SETTINGS };