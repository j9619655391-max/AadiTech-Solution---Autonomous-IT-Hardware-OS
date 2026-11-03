import React, { useState } from 'react';
import {
  Server,
  Shield,
  Layers,
  RefreshCw,
  Terminal,
  Activity,
  CheckCircle2,
  AlertTriangle,
  Radio,
  FileSpreadsheet,
  Truck,
  Package,
  CreditCard,
  MessageSquare,
  Globe,
  Play,
  RotateCw,
  Code2,
  Building2,
  Sliders,
  Database
} from 'lucide-react';
import {
  TenantAccount,
  UserRoleDefinition,
  SystemHealthMetric,
  DeadLetterJob,
  IntegrationConnector,
  ApiEndpointDoc
} from '../types';
import { HostingerMySQLManager } from './HostingerMySQLManager';

interface SystemHubViewProps {
  tenants: TenantAccount[];
  onSwitchTenant: (tenantId: string) => void;
  userRoles: UserRoleDefinition[];
  systemHealth: SystemHealthMetric[];
  deadLetterJobs: DeadLetterJob[];
  onRetryDeadLetterJob: (jobId: string) => void;
  integrations: IntegrationConnector[];
  onToggleIntegration: (id: string) => void;
  apiEndpoints: ApiEndpointDoc[];
}

export const SystemHubView: React.FC<SystemHubViewProps> = ({
  tenants,
  onSwitchTenant,
  userRoles,
  systemHealth,
  deadLetterJobs,
  onRetryDeadLetterJob,
  integrations,
  onToggleIntegration,
  apiEndpoints
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'OBSERVABILITY' | 'TENANTS_RBAC' | 'DLQ' | 'INTEGRATIONS' | 'API_SANDBOX' | 'HOSTINGER_MYSQL'>('HOSTINGER_MYSQL');
  const [selectedEndpoint, setSelectedEndpoint] = useState<ApiEndpointDoc>(apiEndpoints[0]);
  const [apiExecutionStatus, setApiExecutionStatus] = useState<string | null>(null);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const [activeRoleFilter, setActiveRoleFilter] = useState<string>('ALL');

  const currentTenant = tenants.find(t => t.isCurrent) || tenants[0];

  const handleExecuteApi = () => {
    setApiExecutionStatus('EXECUTING');
    setTimeout(() => {
      setApiExecutionStatus('SUCCESS');
      setToastMessage(`Simulated 200 OK returned for ${selectedEndpoint.method} ${selectedEndpoint.path}`);
      setTimeout(() => setToastMessage(null), 3000);
    }, 600);
  };

  const handleRetryJob = (jobId: string) => {
    onRetryDeadLetterJob(jobId);
    setToastMessage(`Dispatched retry payload for job ${jobId} to event broker queue.`);
    setTimeout(() => setToastMessage(null), 3500);
  };

  const getConnectorIcon = (iconType: string) => {
    switch (iconType) {
      case 'FileSpreadsheet': return <FileSpreadsheet className="w-5 h-5 text-emerald-600" />;
      case 'Truck': return <Truck className="w-5 h-5 text-blue-600" />;
      case 'Package': return <Package className="w-5 h-5 text-amber-600" />;
      case 'CreditCard': return <CreditCard className="w-5 h-5 text-indigo-600" />;
      case 'MessageSquare': return <MessageSquare className="w-5 h-5 text-emerald-600" />;
      default: return <Globe className="w-5 h-5 text-slate-600" />;
    }
  };

  const filteredRoles = activeRoleFilter === 'ALL'
    ? userRoles
    : userRoles.filter(r => r.roleId === activeRoleFilter);

  return (
    <div id="system-hub-container" className="space-y-6">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 text-white shadow-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-emerald-500/20 text-emerald-400 rounded-lg border border-emerald-500/30">
              <Server className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight text-slate-100">Enterprise System Hub & Observability</h1>
              <p className="text-xs text-slate-400">
                Multi-tenant GST routing, RBAC matrix, service telemetry, dead letter queue (DLQ), and OpenAPI sandbox.
              </p>
            </div>
          </div>
        </div>

        {/* Current Active Tenant Pill */}
        <div className="flex items-center gap-2 bg-slate-800/90 border border-slate-700/80 px-3 py-1.5 rounded-lg text-xs">
          <Building2 className="w-4 h-4 text-indigo-400 shrink-0" />
          <div>
            <span className="text-slate-400 text-[10px] block leading-none">Active Branch / Entity</span>
            <span className="font-bold text-slate-100">{currentTenant.companyName}</span>
          </div>
        </div>
      </div>

      {/* Sub-tab Navigation */}
      <div className="flex items-center flex-wrap gap-2 border-b border-slate-200 pb-2">
        <button
          onClick={() => setActiveSubTab('OBSERVABILITY')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'OBSERVABILITY'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-emerald-400" />
          <span>System Heartbeat & Telemetry</span>
        </button>

        <button
          onClick={() => setActiveSubTab('TENANTS_RBAC')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'TENANTS_RBAC'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Shield className="w-3.5 h-3.5 text-blue-400" />
          <span>Multi-Tenant & RBAC Matrix</span>
        </button>

        <button
          onClick={() => setActiveSubTab('DLQ')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'DLQ'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Radio className="w-3.5 h-3.5 text-rose-400" />
          <span>Dead Letter Queue (DLQ)</span>
          {deadLetterJobs.length > 0 && (
            <span className="px-1.5 py-0.2 bg-rose-500 text-white text-[10px] font-bold rounded-full">
              {deadLetterJobs.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveSubTab('INTEGRATIONS')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'INTEGRATIONS'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-amber-400" />
          <span>Ecosystem Connectors</span>
        </button>

        <button
          onClick={() => setActiveSubTab('API_SANDBOX')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'API_SANDBOX'
              ? 'bg-slate-900 text-white shadow-sm'
              : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'
          }`}
        >
          <Terminal className="w-3.5 h-3.5 text-indigo-400" />
          <span>OpenAPI / REST Sandbox</span>
        </button>

        <button
          id="tab-hostinger-mysql"
          onClick={() => setActiveSubTab('HOSTINGER_MYSQL')}
          className={`px-3.5 py-1.5 text-xs font-semibold rounded-lg transition-colors flex items-center gap-1.5 ${
            activeSubTab === 'HOSTINGER_MYSQL'
              ? 'bg-amber-600 text-white shadow-sm'
              : 'text-slate-700 hover:text-slate-900 hover:bg-slate-100 border border-amber-200/60 bg-amber-50/50'
          }`}
        >
          <Database className="w-3.5 h-3.5 text-amber-500" />
          <span>Hostinger MySQL & Deploy</span>
          <span className="px-1.5 py-0.2 bg-amber-500/20 text-amber-800 text-[10px] font-bold rounded">
            MySQL
          </span>
        </button>
      </div>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="flex items-center gap-2 p-3 bg-emerald-950/90 border border-emerald-700/60 text-emerald-200 rounded-lg text-xs animate-fadeIn">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* SUB-TAB 1: SYSTEM HEARTBEAT & TELEMETRY */}
      {activeSubTab === 'OBSERVABILITY' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Overall Cluster Availability</div>
              <div className="text-2xl font-bold text-emerald-600 mt-1">99.96%</div>
              <p className="text-xs text-slate-500 mt-1">All 8 core services operational across Mumbai & Bangalore zones.</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Average Service Latency</div>
              <div className="text-2xl font-bold text-indigo-600 mt-1">38 ms</div>
              <p className="text-xs text-slate-500 mt-1">Sub-10ms for in-memory Kafka Event Bus and Redis caching layer.</p>
            </div>
            <div className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Active Microservice Endpoints</div>
              <div className="text-2xl font-bold text-slate-900 mt-1">173 Endpoints</div>
              <p className="text-xs text-slate-500 mt-1">REST APIs, Webhook receivers, and pgvector semantic query pipes.</p>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50/70 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-emerald-600" />
                  Distributed Service Heartbeats & Latency Matrix
                </h2>
                <p className="text-xs text-slate-500">Continuous health probes reporting every 15 seconds with auto-remediation triggers.</p>
              </div>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200">
                <span className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></span>
                Live Telemetry Active
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-slate-50 text-slate-600 font-semibold border-b border-slate-200">
                  <tr>
                    <th className="py-3 px-4">Service Name</th>
                    <th className="py-3 px-4">Category</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-center">Latency</th>
                    <th className="py-3 px-4 text-center">Uptime (30D)</th>
                    <th className="py-3 px-4 text-center">Endpoints</th>
                    <th className="py-3 px-4">Last Checked</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {systemHealth.map((sh) => (
                    <tr key={sh.serviceId} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-3 px-4 font-bold text-slate-800">
                        {sh.serviceName}
                      </td>
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium bg-slate-100 text-slate-700">
                          {sh.category}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          <CheckCircle2 className="w-3 h-3 text-emerald-500" />
                          OPERATIONAL
                        </span>
                      </td>
                      <td className="py-3 px-4 text-center font-mono font-medium text-slate-700">
                        {sh.latencyMs} ms
                      </td>
                      <td className="py-3 px-4 text-center font-bold text-slate-800">
                        {sh.uptimePercentage}%
                      </td>
                      <td className="py-3 px-4 text-center text-slate-600 font-medium">
                        {sh.endpointsActive}
                      </td>
                      <td className="py-3 px-4 text-slate-500">
                        {sh.lastChecked}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 2: MULTI-TENANT & RBAC */}
      {activeSubTab === 'TENANTS_RBAC' && (
        <div className="space-y-6">
          {/* Multi-Tenant Switcher Section */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm space-y-4">
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Building2 className="w-4 h-4 text-indigo-600" />
                Multi-Tenant Operating Entities & Regional Hubs
              </h2>
              <p className="text-xs text-slate-500">
                Switch operating context between separate legal entities with distinct GSTINs, state-tax rules, and isolated storage quotas.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {tenants.map((tenant) => (
                <div
                  key={tenant.id}
                  className={`p-4 rounded-xl border transition-all ${
                    tenant.isCurrent
                      ? 'bg-indigo-50/50 border-indigo-400 shadow-sm'
                      : 'bg-white border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-xs font-bold text-indigo-700 bg-indigo-100/70 px-2 py-0.5 rounded">
                      {tenant.tenantCode}
                    </span>
                    {tenant.isCurrent ? (
                      <span className="px-2 py-0.5 bg-indigo-600 text-white text-[10px] font-bold rounded-full flex items-center gap-1">
                        <CheckCircle2 className="w-3 h-3" />
                        ACTIVE CONTEXT
                      </span>
                    ) : (
                      <button
                        onClick={() => {
                          onSwitchTenant(tenant.id);
                          setToastMessage(`Switched tenant context to: ${tenant.companyName}`);
                          setTimeout(() => setToastMessage(null), 3000);
                        }}
                        className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 hover:underline"
                      >
                        Switch To This
                      </button>
                    )}
                  </div>

                  <h3 className="text-sm font-bold text-slate-900 leading-tight">{tenant.companyName}</h3>
                  <div className="mt-2 text-xs text-slate-600 space-y-1">
                    <div>GSTIN: <span className="font-mono font-medium text-slate-800">{tenant.gstin}</span></div>
                    <div>State: <span className="font-medium text-slate-800">{tenant.stateCode}</span></div>
                    <div>Currency: <span className="font-medium text-slate-800">{tenant.operatingCurrency}</span></div>
                    <div>Active Users: <span className="font-bold text-slate-900">{tenant.activeUsersCount}</span></div>
                    <div>
                      Quota Used: <span className="font-semibold text-slate-800">{tenant.storageUsedMb} MB</span> / {tenant.storageQuotaMb} MB
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* RBAC Role Matrix */}
          <div className="bg-white rounded-xl border border-slate-200 shadow-sm overflow-hidden">
            <div className="p-4 border-b border-slate-100 bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-blue-600" />
                  Granular Role-Based Access Control (RBAC) Governance Matrix
                </h2>
                <p className="text-xs text-slate-500">Explicit authority scopes preventing unauthorized commercial discounting or data manipulation.</p>
              </div>

              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500 font-medium">Filter Role:</span>
                <select
                  value={activeRoleFilter}
                  onChange={(e) => setActiveRoleFilter(e.target.value)}
                  className="text-xs bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 font-medium focus:outline-none focus:ring-1 focus:ring-indigo-500"
                >
                  <option value="ALL">All Roles (6)</option>
                  <option value="SUPER_ADMIN">Super Admin</option>
                  <option value="BUSINESS_OWNER">Business Owner</option>
                  <option value="SALES_MANAGER">Sales Manager</option>
                  <option value="PURCHASE_MANAGER">Purchase Manager</option>
                  <option value="WAREHOUSE_MANAGER">Warehouse Manager</option>
                  <option value="FINANCE_MANAGER">Finance Manager</option>
                </select>
              </div>
            </div>

            <div className="p-4 space-y-4">
              {filteredRoles.map((role) => (
                <div key={role.roleId} className="border border-slate-200 rounded-xl p-4 space-y-2.5 bg-white">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold bg-slate-100 text-slate-800 px-2 py-0.5 rounded">
                        {role.roleId}
                      </span>
                      <h3 className="text-sm font-bold text-slate-900">{role.roleName}</h3>
                    </div>
                    <span className="text-xs font-medium text-slate-500 bg-slate-50 px-2 py-0.5 rounded border border-slate-200">
                      Department: {role.department}
                    </span>
                  </div>

                  <p className="text-xs text-slate-600">{role.description}</p>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs">
                    <div className="bg-emerald-50/60 border border-emerald-200 rounded-lg p-3">
                      <div className="font-bold text-emerald-900 mb-1.5 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                        Authorized Actions ({role.allowedActions.length})
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {role.allowedActions.map((action, idx) => (
                          <span key={idx} className="font-mono text-[11px] bg-white border border-emerald-300 text-emerald-800 px-2 py-0.5 rounded">
                            {action}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="bg-rose-50/60 border border-rose-200 rounded-lg p-3">
                      <div className="font-bold text-rose-900 mb-1.5 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-rose-600" />
                        Restricted Boundaries ({role.restrictedActions.length})
                      </div>
                      {role.restrictedActions.length === 0 ? (
                        <span className="text-[11px] text-slate-500 italic">No restrictions (Root System Administrator)</span>
                      ) : (
                        <div className="flex flex-wrap gap-1.5">
                          {role.restrictedActions.map((action, idx) => (
                            <span key={idx} className="font-mono text-[11px] bg-white border border-rose-300 text-rose-800 px-2 py-0.5 rounded">
                              {action}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 3: DEAD LETTER QUEUE (DLQ) */}
      {activeSubTab === 'DLQ' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Radio className="w-4 h-4 text-rose-600" />
                Dead Letter Queue (DLQ) & Webhook Resilience Console
              </h2>
              <p className="text-xs text-slate-500">
                Catches transient failures from third-party logistics, lead portals, and payment webhooks with exponential backoff retries.
              </p>
            </div>
            <div className="text-xs bg-slate-100 text-slate-700 px-3 py-1.5 rounded-lg font-medium">
              Auto-retry policy: Exponential Backoff (1m, 5m, 15m, 1h)
            </div>
          </div>

          <div className="space-y-3">
            {deadLetterJobs.map((job) => (
              <div key={job.id} className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm space-y-3">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-100 pb-3">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs font-bold bg-slate-100 text-slate-800 px-2 py-0.5 rounded">
                      {job.id}
                    </span>
                    <h3 className="text-sm font-bold text-slate-900">{job.jobName}</h3>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      job.status === 'RESOLVED'
                        ? 'bg-emerald-100 text-emerald-800'
                        : job.status === 'RETRYING'
                        ? 'bg-amber-100 text-amber-800'
                        : 'bg-rose-100 text-rose-800'
                    }`}>
                      {job.status}
                    </span>
                  </div>

                  <div className="text-xs text-slate-500">
                    Failed At: <span className="font-medium text-slate-700">{job.failedAt}</span>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500">Source: </span>
                    <span className="font-semibold text-slate-800">{job.sourceModule}</span>
                    <span className="text-slate-400 mx-1.5">→</span>
                    <span className="text-slate-500">Target: </span>
                    <span className="font-semibold text-slate-800">{job.targetDestination}</span>
                  </div>

                  <div className="text-right">
                    <span className="text-slate-500">Retry Counter: </span>
                    <span className="font-bold text-slate-900">{job.retryCount} / {job.maxRetries}</span>
                  </div>
                </div>

                {/* Error Box */}
                <div className="bg-rose-50 border border-rose-200 rounded-lg p-3 text-xs">
                  <div className="font-bold text-rose-900 mb-0.5">Failure Diagnostic:</div>
                  <div className="font-mono text-rose-800">{job.errorMessage}</div>
                  <div className="text-slate-600 mt-1.5 font-medium">Payload Summary: {job.payloadSummary}</div>
                </div>

                {/* Action */}
                <div className="flex items-center justify-end gap-2 pt-1">
                  {job.status === 'RESOLVED' ? (
                    <span className="inline-flex items-center gap-1 text-xs font-bold text-emerald-700 bg-emerald-50 px-3 py-1.5 rounded-lg border border-emerald-200">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600" />
                      Payload Resolved & Ingested
                    </span>
                  ) : (
                    <button
                      onClick={() => handleRetryJob(job.id)}
                      className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors flex items-center gap-1.5"
                    >
                      <RotateCw className="w-3.5 h-3.5" />
                      <span>Re-Dispatch Webhook Payload</span>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUB-TAB 4: ECOSYSTEM CONNECTORS */}
      {activeSubTab === 'INTEGRATIONS' && (
        <div className="space-y-4">
          <div className="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-3">
            <div>
              <h2 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Layers className="w-4 h-4 text-amber-600" />
                Enterprise Hardware Ecosystem Integrations
              </h2>
              <p className="text-xs text-slate-500">
                Bidirectional synchronization with Tally Prime, Indian logistics providers, Razorpay settlement, and WhatsApp Cloud APIs.
              </p>
            </div>
            <span className="text-xs font-semibold text-emerald-700 bg-emerald-50 px-3 py-1.5 rounded-lg border border-emerald-200">
              All 6 connectors synchronized today
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {integrations.map((connector) => (
              <div key={connector.id} className="bg-white border border-slate-200 rounded-xl p-4 shadow-sm hover:border-slate-300 transition-colors space-y-3">
                <div className="flex items-start justify-between">
                  <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-100">
                    {getConnectorIcon(connector.iconType)}
                  </div>
                  <button
                    onClick={() => {
                      onToggleIntegration(connector.id);
                      setToastMessage(`Toggled connector state for ${connector.name}`);
                      setTimeout(() => setToastMessage(null), 2500);
                    }}
                    className={`px-2.5 py-1 rounded-full text-[11px] font-bold transition-colors ${
                      connector.connectionStatus === 'CONNECTED'
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100'
                        : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                    }`}
                  >
                    {connector.connectionStatus}
                  </button>
                </div>

                <div>
                  <h3 className="text-sm font-bold text-slate-900">{connector.name}</h3>
                  <p className="text-xs text-slate-500">{connector.provider}</p>
                </div>

                <div className="text-xs text-slate-600 space-y-1 bg-slate-50 p-2.5 rounded-lg border border-slate-100">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Last Synced:</span>
                    <span className="font-medium text-slate-800">{connector.lastSyncTimestamp}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Synced Today:</span>
                    <span className="font-bold text-slate-900">{connector.syncedRecordsToday} records</span>
                  </div>
                  <div className="truncate font-mono text-[10px] text-slate-400 mt-1">
                    {connector.endpointUrl}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* SUB-TAB 5: INTERACTIVE OPENAPI / REST SANDBOX */}
      {activeSubTab === 'API_SANDBOX' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
          {/* Left: Endpoint List */}
          <div className="lg:col-span-4 bg-white rounded-xl border border-slate-200 shadow-sm p-4 space-y-3">
            <h2 className="text-xs font-bold text-slate-900 uppercase tracking-wider">Available REST Endpoints</h2>
            <div className="space-y-1.5">
              {apiEndpoints.map((ep) => (
                <button
                  key={ep.id}
                  onClick={() => setSelectedEndpoint(ep)}
                  className={`w-full text-left p-2.5 rounded-lg text-xs transition-colors flex items-center justify-between ${
                    selectedEndpoint.id === ep.id
                      ? 'bg-slate-900 text-white font-semibold'
                      : 'hover:bg-slate-100 text-slate-700'
                  }`}
                >
                  <div className="flex items-center gap-2 truncate">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                      ep.method === 'GET'
                        ? 'bg-emerald-500 text-white'
                        : ep.method === 'POST'
                        ? 'bg-blue-500 text-white'
                        : 'bg-amber-500 text-white'
                    }`}>
                      {ep.method}
                    </span>
                    <span className="font-mono truncate">{ep.path}</span>
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Right: Endpoint Inspector & Execution */}
          <div className="lg:col-span-8 bg-white rounded-xl border border-slate-200 shadow-sm p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-0.5 rounded text-xs font-mono font-bold ${
                    selectedEndpoint.method === 'GET'
                      ? 'bg-emerald-100 text-emerald-800'
                      : 'bg-blue-100 text-blue-800'
                  }`}>
                    {selectedEndpoint.method}
                  </span>
                  <span className="font-mono text-sm font-bold text-slate-900">{selectedEndpoint.path}</span>
                </div>
                <p className="text-xs text-slate-500 mt-1">{selectedEndpoint.summary}</p>
              </div>

              <button
                onClick={handleExecuteApi}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors flex items-center gap-1.5 shrink-0"
              >
                <Play className="w-3.5 h-3.5 fill-white" />
                <span>Execute Sandbox Call</span>
              </button>
            </div>

            {/* Response Section */}
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-slate-700 flex items-center gap-1.5">
                  <Code2 className="w-4 h-4 text-slate-500" />
                  Response Payload (application/json)
                </span>
                <span className="text-slate-400 font-mono text-[11px]">HTTP 200 OK • Content-Type: application/json</span>
              </div>

              <pre className="bg-slate-950 text-emerald-400 p-4 rounded-xl text-xs font-mono overflow-x-auto border border-slate-800 leading-relaxed shadow-inner">
                {selectedEndpoint.sampleResponse}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* SUB-TAB 6: HOSTINGER MYSQL & DEPLOYMENT */}
      {activeSubTab === 'HOSTINGER_MYSQL' && (
        <HostingerMySQLManager />
      )}
    </div>
  );
};
