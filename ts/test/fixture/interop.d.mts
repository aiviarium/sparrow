export function facets(lib: any): { server: any; client: any; serverSchema: any; clientSchema: any };
export function serverHandlers(lib: any): { state: { lastLog: string; cancelled: boolean }; handlers: any };
export function clientHandlers(): any;
export function everything(): any;
export function runClientSuite(session: any, lib: any, log?: (s: string) => void): Promise<string[]>;
