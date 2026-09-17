export interface BaseHost {
  name: string;
  host: string;
  port: number;
  username: string;
  remoteRoot: string; // normalized, absolute POSIX
  localRoot: string; // realpath
  allowOverwrite: boolean;
  maxBytes?: number;
  connectTimeoutMs: number;
}

export type SftpAuth =
  | { type: 'password'; password: string }
  | { type: 'key'; privateKey: Buffer; passphrase?: string }
  | { type: 'agent'; agentSocket: string };

export interface SftpHost extends BaseHost {
  protocol: 'sftp';
  auth: SftpAuth;
  hostKeySha256?: string[];
  knownHosts?: string; // file content, read at startup
}

export interface FtpsHost extends BaseHost {
  protocol: 'ftps';
  password: string;
  tls?: 'explicit' | 'implicit'; // undefined only when insecurePlainFtp was set
  ca?: string; // PEM content
}

export type HostConfig = SftpHost | FtpsHost;

export interface Config {
  hosts: Map<string, HostConfig>;
  secrets: string[];
}

export type EntryType = 'file' | 'dir' | 'link' | 'other';

export interface Entry {
  name: string;
  type: EntryType;
  size: number;
  modifiedAt: string | null;
}

export type StatResult =
  | { exists: false }
  | { exists: true; type: EntryType; size: number; modifiedAt: string | null };

export interface UploadResult {
  remotePath: string;
  bytes: number;
  overwritten: boolean;
}

export const MAX_ENTRIES = 1000;
