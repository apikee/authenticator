import { NextFunction, Request, Response } from "express";
import { Store } from "../stores/Store";

export interface AuthenticatorProps {
  accessKey: string;
  refreshKey: string;
  domain?: string;
  accessExpiresInSeconds?: number;
  refreshExpiresInSeconds?: number;
  sameSite?: "lax" | "none" | "strict";
  store?: Store;
  rejectedAccessHandler?: (
    req: Request,
    res: Response,
    next: NextFunction
  ) => void;
}
