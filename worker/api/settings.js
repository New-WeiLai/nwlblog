import { Database, DEFAULT_SETTINGS } from '../utils/db.js';

export class SettingsAPI {
    constructor(env) {
        this.db = new Database(env.BLOG_KV);
    }

    // 获取站点设置（公开）
    async getPublicSettings() {
        const settings = await this.db.getSettings();
        // 只返回公开的设置
        return {
            siteTitle: settings.siteTitle,
            siteDescription: settings.siteDescription,
            headerImage: settings.headerImage,
            backgroundImage: settings.backgroundImage,
            footerText: settings.footerText,
            postsPerPage: settings.postsPerPage,
            enableComments: settings.enableComments
        };
    }

    // 获取所有设置（管理员）
    async getAllSettings(operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role === 'user') {
            throw new Error('没有权限查看所有设置');
        }

        return await this.db.getSettings();
    }

    // 更新设置（管理员）
    async updateSettings(newSettings, operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role === 'user') {
            throw new Error('没有权限修改设置');
        }

        // 超级管理员可以修改所有设置
        // 普通管理员只能修改部分设置
        if (operator.role === 'admin') {
            // 限制管理员不能修改某些关键设置
            const restrictedFields = ['allowRegistration', 'requireEmailVerification'];
            for (const field of restrictedFields) {
                if (field in newSettings) {
                    delete newSettings[field];
                }
            }
        }

        const updated = await this.db.updateSettings(newSettings);
        return updated;
    }

    // 重置为默认设置
    async resetSettings(operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role !== 'super_admin') {
            throw new Error('只有超级管理员可以重置设置');
        }

        await this.db.kv.put('site_settings', JSON.stringify(DEFAULT_SETTINGS));
        return DEFAULT_SETTINGS;
    }

    // 获取站点统计
    async getSiteStats() {
        return await this.db.getStats();
    }

    // 上传图片（头图、背景图等）
    async uploadImage(file, type, operatorId) {
        const operator = await this.db.getUserById(operatorId);
        if (operator.role === 'user') {
            throw new Error('没有权限上传图片');
        }

        // 这里应该将图片上传到 R2 或外部存储
        // 简单起见，这里返回一个模拟的 URL
        const fileName = `${Date.now()}-${file.name}`;
        const url = `/uploads/${fileName}`;

        // 更新设置中的图片路径
        if (type === 'header') {
            await this.db.updateSettings({ headerImage: url });
        } else if (type === 'background') {
            await this.db.updateSettings({ backgroundImage: url });
        }

        return { url };
    }
}