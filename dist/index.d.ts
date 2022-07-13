export * from "./Authenticator";
export * from "./MemoryStore";
export * from "./cookieParser";
declare global {
    namespace Express {
        interface Request {
            subject: string;
        }
        interface Response {
            subject: string;
            payload?: any;
        }
    }
}
