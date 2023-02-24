export interface SimpleSignableRequest {
  host: string;
  endpoint: string;
  headers: Record<string, string | string[]>;
  payload: Record<string, any>;
}
