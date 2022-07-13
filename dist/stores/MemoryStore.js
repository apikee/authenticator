"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryStore = void 0;
const stores_1 = require("../stores");
class MemoryStore extends stores_1.Store {
    _data = {};
    _getTokenBySubject = (subject) => {
        return Object.keys(this._data).find((key) => this._data[key] === subject);
    };
    addToken = (token, subject, replace = false) => {
        if (replace) {
            const usedToken = this._getTokenBySubject(subject);
            usedToken && this.deleteToken(usedToken);
        }
        this._data[token] = subject;
    };
    findSubjectByToken = (token) => {
        return this._data[token];
    };
    deleteToken = (token) => {
        delete this._data[token];
    };
    deleteAllTokensForSubject = (subject) => {
        Object.keys(this._data)
            .filter((key) => this._data[key] === subject)
            .forEach((token) => this.deleteToken(token));
    };
    clearExpiredTokens = async (validateToken) => {
        await Promise.all(Object.keys(this._data).map((token) => {
            if (!validateToken("refresh", token)) {
                this.deleteToken(token);
            }
        }));
    };
}
exports.MemoryStore = MemoryStore;
