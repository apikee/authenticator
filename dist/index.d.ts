export * from "./Authenticator";
export * from "./stores";
export * from "./cookieParser";
declare global {
    namespace Express {
        interface Request {
            subject: string | any;
            payload?: any;
        }
        interface Response {
            subject: string;
            payload?: any;
        }
    }
}
