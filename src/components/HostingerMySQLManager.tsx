import React, { useState, useEffect } from 'react';
import {
  Database,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Copy,
  Download,
  Server,
  ExternalLink,
  ShieldCheck,
  FileCode,
  Globe,
  Terminal,
  Layers,
  HelpCircle,
  Key
} from 'lucide-react';

interface DbStatus {
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

export const HostingerMySQLManager: React.FC = () => {
  const [dbStatus, setDbStatus] = useState<DbStatus | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [copied, setCopied] = useState<string | null>(null);
  const [sqlSchema, setSqlSchema] = useState<string>('');
  const [loadingSchema, setLoadingSchema] = useState<boolean>(false);

  // Custom configuration helper generator
  const [configForm, setConfigForm] = useState({
    dbHost: 'localhost',
    dbPort: '3306',
    dbName: 'u123456789_ithardware',
    dbUser: 'u123456789_admin',
    dbPass: 'SecureP@ss2026#'
  });

  const fetchDbStatus = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/db/status');
      const data = await res.json();
      setDbStatus(data);
    } catch (err: any) {
      setDbStatus({
        isConfigured: false,
        isConnected: false,
        host: 'localhost',
        database: 'Not Set',
        user: 'Not Set',
        port: 3306,
        message: 'Could not communicate with database check endpoint',
        tableCount: 0,
        tables: []
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchSqlSchema = async () => {
    setLoadingSchema(true);
    try {
      const res = await fetch('/api/db/schema-sql');
      const text = await res.text();
      setSqlSchema(text);
    } catch (err) {
      setSqlSchema('-- Failed to fetch schema.sql');
    } finally {
      setLoadingSchema(false);
    }
  };

  useEffect(() => {
    fetchDbStatus();
    fetchSqlSchema();
  }, []);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 3000);
  };

  const handleDownloadSchema = () => {
    const blob = new Blob([sqlSchema], { type: 'text/sql' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'schema.sql';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const generatedEnvSnippet = `# Hostinger MySQL Configuration
DB_HOST=${configForm.dbHost}
DB_PORT=${configForm.dbPort}
DB_USER=${configForm.dbUser}
DB_PASSWORD=${configForm.dbPass}
DB_NAME=${configForm.dbName}
DB_SSL=false`;

  return (
    <div id="hostinger-mysql-manager" className="space-y-6">
      {/* Top Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-slate-800 rounded-xl p-5 text-white shadow-md">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-amber-500/20 text-amber-400 rounded-xl border border-amber-500/30 shrink-0">
              <Database className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white">Hostinger Business Plan & MySQL Hub</h2>
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  Target: Hostinger Shared Hosting
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1 max-w-2xl">
                Deploy <strong>IT Hardware Platform</strong> directly to your Hostinger Business Web Hosting plan.
                Uses standard <strong>MySQL 8.0+ / MariaDB</strong> via phpMyAdmin, with LiteSpeed SPA routing (`.htaccess`) and Node.js process management.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              id="btn-refresh-mysql-status"
              onClick={fetchDbStatus}
              disabled={loading}
              className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-amber-400' : 'text-slate-400'}`} />
              <span>Test Connection</span>
            </button>

            <button
              id="btn-download-schema"
              onClick={handleDownloadSchema}
              className="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Download schema.sql</span>
            </button>
          </div>
        </div>
      </div>

      {/* Diagnostics & Connection Status Card */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Status Card */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">MySQL Status</span>
            {dbStatus?.isConnected ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 border border-emerald-200">
                <CheckCircle2 className="w-3 h-3 text-emerald-600" />
                Live MySQL Connected
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 border border-amber-200">
                <AlertTriangle className="w-3 h-3 text-amber-600" />
                Standalone / Dev Mode
              </span>
            )}
          </div>

          <div className="mt-3">
            <p className="text-sm font-bold text-slate-800">
              {dbStatus?.isConnected ? `Connected to ${dbStatus.database}` : 'Dev Environment (Simulated)'}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">{dbStatus?.message}</p>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 flex items-center justify-between text-xs text-slate-600">
            <span>Tables Detected:</span>
            <span className="font-mono font-bold text-slate-900">{dbStatus?.tableCount || 0} tables</span>
          </div>
        </div>

        {/* Hostinger Config Overview */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Hostinger Target Specs</span>
          <div className="mt-3 space-y-1.5 text-xs text-slate-700">
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Database Engine:</span>
              <strong className="text-slate-900 font-mono">MySQL 8.0 / MariaDB</strong>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">DB Host:</span>
              <strong className="text-slate-900 font-mono">localhost:3306</strong>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Web Server:</span>
              <strong className="text-slate-900 font-mono">LiteSpeed + .htaccess</strong>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-500">Management UI:</span>
              <strong className="text-slate-900 font-mono">phpMyAdmin in hPanel</strong>
            </div>
          </div>

          <div className="mt-3 pt-2 border-t border-slate-100 flex items-center gap-1 text-[11px] text-indigo-600">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Standard Hostinger Business Plan Compatible</span>
          </div>
        </div>

        {/* Ready Files */}
        <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
          <span className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Production Artifacts</span>
          <div className="mt-3 space-y-2 text-xs">
            <div className="flex items-center justify-between">
              <span className="font-mono text-slate-700">/database/schema.sql</span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold text-[10px]">READY</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-slate-700">/public/.htaccess</span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold text-[10px]">READY</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-slate-700">ecosystem.config.cjs</span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold text-[10px]">READY</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="font-mono text-slate-700">HOSTINGER_GUIDE.md</span>
              <span className="px-1.5 py-0.5 rounded bg-emerald-50 text-emerald-700 font-semibold text-[10px]">READY</span>
            </div>
          </div>
        </div>
      </div>

      {/* 5-Step Hostinger Deployment Checklist (Hindi & English) */}
      <div className="bg-white border border-slate-200 rounded-xl p-5 shadow-sm">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-indigo-600" />
            <h3 className="font-bold text-slate-900 text-sm">Hostinger Business Plan: 5-Step Deployment Guide</h3>
          </div>
          <span className="text-xs text-slate-500">Zero Extra Server Cost</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
          {/* Step 1 */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-bold">1</span>
              <span className="font-bold text-xs text-slate-900">Create MySQL</span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Hostinger hPanel ➔ <strong>Databases</strong> ➔ Create DB (e.g. <code className="text-slate-800">u123_ithardware</code>).
            </p>
          </div>

          {/* Step 2 */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-bold">2</span>
              <span className="font-bold text-xs text-slate-900">Import phpMyAdmin</span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Open phpMyAdmin, click <strong>Import</strong>, aur <code className="text-slate-800">database/schema.sql</code> upload karein.
            </p>
          </div>

          {/* Step 3 */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-bold">3</span>
              <span className="font-bold text-xs text-slate-900">Configure .env</span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Apna DB user, password aur DB name <code className="text-slate-800">.env</code> file mein save karein.
            </p>
          </div>

          {/* Step 4 */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-bold">4</span>
              <span className="font-bold text-xs text-slate-900">Node.js Selector</span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              hPanel ➔ <strong>Node.js</strong> ➔ Node 18+ select karein, startup file <code className="text-slate-800">dist/server.cjs</code>.
            </p>
          </div>

          {/* Step 5 */}
          <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 space-y-1.5">
            <div className="flex items-center gap-2">
              <span className="w-5 h-5 rounded-full bg-indigo-600 text-white flex items-center justify-center text-xs font-bold">5</span>
              <span className="font-bold text-xs text-slate-900">Run & Build</span>
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">
              Run <code className="text-slate-800">npm run build</code>. Platform aapke domain par live chalega!
            </p>
          </div>
        </div>
      </div>

      {/* 2-Column: Config Generator & Schema Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: .env Config Generator */}
        <div className="lg:col-span-5 bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4">
          <div className="flex items-center gap-2">
            <Key className="w-4 h-4 text-indigo-600" />
            <h3 className="font-bold text-slate-900 text-sm">Hostinger .env Helper</h3>
          </div>
          <p className="text-xs text-slate-500">
            Apne Hostinger hPanel ke database credentials yahan type karein. Yeh instantly aapko copyable `.env` snippet generate karega:
          </p>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">DB_HOST</label>
              <input
                type="text"
                value={configForm.dbHost}
                onChange={(e) => setConfigForm({ ...configForm, dbHost: e.target.value })}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 font-mono focus:ring-2 focus:ring-indigo-500 outline-none"
              />
              <span className="text-[10px] text-slate-400">Hostinger shared hosting par humesha 'localhost' hota hai.</span>
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">DB_NAME</label>
              <input
                type="text"
                value={configForm.dbName}
                onChange={(e) => setConfigForm({ ...configForm, dbName: e.target.value })}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 font-mono focus:ring-2 focus:ring-indigo-500 outline-none"
                placeholder="u123456789_ithardware"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">DB_USER</label>
              <input
                type="text"
                value={configForm.dbUser}
                onChange={(e) => setConfigForm({ ...configForm, dbUser: e.target.value })}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 font-mono focus:ring-2 focus:ring-indigo-500 outline-none"
                placeholder="u123456789_admin"
              />
            </div>

            <div>
              <label className="block text-xs font-semibold text-slate-700 mb-1">DB_PASSWORD</label>
              <input
                type="text"
                value={configForm.dbPass}
                onChange={(e) => setConfigForm({ ...configForm, dbPass: e.target.value })}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-slate-300 font-mono focus:ring-2 focus:ring-indigo-500 outline-none"
                placeholder="Your MySQL password"
              />
            </div>
          </div>

          <div className="pt-2">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="font-semibold text-slate-700">Ready-to-Paste Snippet:</span>
              <button
                onClick={() => handleCopy(generatedEnvSnippet, 'env')}
                className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold flex items-center gap-1"
              >
                <Copy className="w-3 h-3" />
                <span>{copied === 'env' ? 'Copied!' : 'Copy .env'}</span>
              </button>
            </div>
            <pre className="p-3 bg-slate-900 text-emerald-400 rounded-lg text-xs font-mono overflow-x-auto leading-relaxed border border-slate-800">
              {generatedEnvSnippet}
            </pre>
          </div>
        </div>

        {/* Right Column: SQL Schema Viewer & phpMyAdmin 1-Click Copy */}
        <div className="lg:col-span-7 bg-white border border-slate-200 rounded-xl p-5 shadow-sm space-y-4 flex flex-col">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-amber-600" />
              <h3 className="font-bold text-slate-900 text-sm">MySQL DDL Schema (/database/schema.sql)</h3>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => handleCopy(sqlSchema, 'sql')}
                className="px-2.5 py-1 text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg transition-colors flex items-center gap-1"
              >
                <Copy className="w-3 h-3" />
                <span>{copied === 'sql' ? 'Copied All SQL!' : 'Copy All SQL'}</span>
              </button>
              <button
                onClick={handleDownloadSchema}
                className="px-2.5 py-1 text-xs font-semibold bg-amber-50 hover:bg-amber-100 text-amber-800 border border-amber-200 rounded-lg transition-colors flex items-center gap-1"
              >
                <Download className="w-3 h-3" />
                <span>Download .sql</span>
              </button>
            </div>
          </div>

          <p className="text-xs text-slate-500">
            Is SQL ko Hostinger phpMyAdmin ke <strong>SQL</strong> tab mein paste karke <strong>Go</strong> dabayein, ya <strong>Import</strong> tab se direct upload karein:
          </p>

          <div className="flex-1 min-h-[340px] max-h-[460px] overflow-y-auto bg-slate-950 text-slate-200 p-4 rounded-xl font-mono text-xs leading-relaxed border border-slate-800 shadow-inner">
            {loadingSchema ? (
              <div className="flex items-center justify-center h-full text-slate-400">Loading SQL schema...</div>
            ) : (
              <pre>{sqlSchema || '-- SQL Schema loading...'}</pre>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
