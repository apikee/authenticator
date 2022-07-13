"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cookieParser = void 0;
const cookieParser = (input) => {
    return input
        .split(";")
        .map((v) => v.split("="))
        .reduce((acc, v) => {
        acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
        return acc;
    }, {});
};
exports.cookieParser = cookieParser;
