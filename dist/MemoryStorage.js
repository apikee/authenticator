"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MemoryStore = void 0;
class MemoryStore {
    allowMultipleLocations = true;
    _data = {
        token123: "user1",
        token456: "user2",
    };
    _getTokenBySubject = (subject) => {
        return Object.keys(this._data).find((key) => this._data[key] === subject);
    };
    add = (token, subject) => {
        this._data[token] = subject;
    };
}
exports.MemoryStore = MemoryStore;
