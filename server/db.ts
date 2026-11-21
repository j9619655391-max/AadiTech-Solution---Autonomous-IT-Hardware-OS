import mysql from 'mysql2/promise';

type Pool = ReturnType<typeof mysql.createPool>;

export interface DatabaseStatus {
  isConfigured: boolean;
  isConnected: boolean;
  host: string;
  database: string;
  user: string;
  port: number;
  message: string;
  tableCount: number;
  tables: string[];
}

let pool: Pool | null = null;

export function getDatabaseConfig() {
  const host = process.env.DB_HOST || '';
  const user = process.env.DB_USER || '';
  const password = process.env.DB_PASSWORD || '';
  const database = process.env.DB_NAME || '';
  const port = parseInt(process.env.DB_PORT || '3306', 10);
  if (process.env.DB_SSL && !['true','false'].includes(process.env.DB_SSL)) {
    throw new Error('DB_SSL must be explicitly true or false');
  }
  const caBase64=process.env.DB_SSL_CA_BASE64;
  if(caBase64 && process.env.DB_SSL!=='true') {
    throw new Error('DB_SSL_CA_BASE64 requires DB_SSL=true');
  }
  let ssl:{rejectUnauthorized:true;ca?:string}|undefined;
  if(process.env.DB_SSL==='true') {
    ssl={rejectUnauthorized:true};
    if(caBase64) {
      const decoded=Buffer.from(caBase64,'base64').toString('utf8');
      if(!decoded.includes('-----BEGIN CERTIFICATE-----') ||
         !decoded.includes('-----END CERTIFICATE-----')) {
        throw new Error('DB_SSL_CA_BASE64 must contain a PEM certificate');
      }
      ssl.ca=decoded;
    }
  }

  return { host, user, password, database, port, ssl };
}

export function getPool(): Pool | null {
  const config = getDatabaseConfig();
  if (!config.host || !config.database) {
    return null;
  }

  if (!pool) {
    try {
      pool = mysql.createPool({
        host: config.host,
        user: config.user,
        password: config.password,
        database: config.database,
        port: config.port,
        ssl: config.ssl,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        keepAliveInitialDelay: 10000
      });
    } catch (err) {
      console.error('Failed to initialize MySQL pool:', err);
      pool = null;
    }
  }

  return pool;
}

export async function checkDatabaseConnection(): Promise<DatabaseStatus> {
  const config = getDatabaseConfig();

  if (!config.host || !config.database) {
    return {
      isConfigured: false,
      isConnected: false,
      host: config.host || 'Not Set',
      database: config.database || 'Not Set',
      user: config.user || 'Not Set',
      port: config.port,
      message: 'Hostinger MySQL environment variables (DB_HOST, DB_NAME, DB_USER) not configured.',
      tableCount: 0,
      tables: []
    };
  }

  try {
    const currentPool = getPool();
    if (!currentPool) {
      throw new Error('Could not establish connection pool');
    }

    const connection = await currentPool.getConnection();
    try {
      const [rows] = await connection.query('SHOW TABLES');
      const tableRows = rows as any[];
      const tables: string[] = tableRows.map((r: any) => Object.values(r)[0] as string);

      return {
        isConfigured: true,
        isConnected: true,
        host: config.host,
        database: config.database,
        user: config.user,
        port: config.port,
        message: `Successfully connected to Hostinger MySQL (${tables.length} tables found).`,
        tableCount: tables.length,
        tables
      };
    } finally {
      connection.release();
    }
  } catch (err: any) {
    return {
      isConfigured: true,
      isConnected: false,
      host: config.host,
      database: config.database,
      user: config.user,
      port: config.port,
      message: 'MySQL connection failed; inspect protected server logs for diagnostics.',
      tableCount: 0,
      tables: []
    };
  }
}
