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
  const ssl = process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : undefined;

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
      message: `MySQL Connection Failed: ${err.message || String(err)}`,
      tableCount: 0,
      tables: []
    };
  }
}
