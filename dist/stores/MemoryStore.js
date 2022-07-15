"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryStore = void 0;
const Store_1 = require("./Store");
class MemoryStore extends Store_1.Store {
    _data = {};
    addToken = async (token, subject, replace = false) => {
        if (replace) {
            const usedTokens = Object.keys(this._data).filter((token) => this._data[token] === subject);
            await Promise.all(usedTokens.map((token) => this.deleteToken(token)));
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
