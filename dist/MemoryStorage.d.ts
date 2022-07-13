export declare class MemoryStore {
    allowMultipleLocations: boolean;
    private _data;
    private _getTokenBySubject;
    add: (token: string, subject: string) => void;
}
