const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

type QueryValue = string | number | boolean | undefined | null;

function buildQuery(params?: Record<string, QueryValue>) {
  const query = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== '' && value !== 'all') {
      query.set(key, String(value));
    }
  });
  const text = query.toString();
  return text ? `?${text}` : '';
}

async function fetchAPI<T>(endpoint: string, options?: RequestInit, fallback?: T): Promise<T> {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...(options?.headers || {}),
      },
    });

    const result = await response.json().catch(() => null);
    if (!response.ok) {
      throw new Error(result?.message || result?.detail || `HTTP ${response.status}: ${response.statusText}`);
    }

    const data = result?.success !== undefined ? result.data : result;
    return data as T;
  } catch (error) {
    console.warn(`Backend API failed for ${endpoint}; using fallback when available`, error);
    if (fallback !== undefined) return fallback;
    throw error instanceof Error ? error : new Error('Không thể kết nối backend');
  }
}

export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type ThreatStatus = 'active' | 'investigating' | 'mitigated';

export interface Feed {
  id: string;
  name: string;
  source_url: string;
  url: string;
  source: string;
  description?: string;
  status: 'active' | 'inactive';
  enabled: boolean;
  last_fetched_at?: string;
  last_updated?: string;
  created_at?: string;
  updated_at?: string;
  alert_count?: number;
}

export interface Alert {
  id: string;
  feed_id?: string;
  feed_name?: string;
  title: string;
  description: string;
  indicator_type: string;
  indicator_value: string;
  indicator?: string;
  severity: Severity;
  confidence?: number;
  risk_score?: number;
  type: string;
  status: ThreatStatus;
  source?: string;
  country?: string;
  country_code?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  lat?: number;
  lng?: number;
  asn?: string;
  reputation?: number;
  mitre_tactic?: string;
  mitre_technique?: string;
  attack_vector?: string;
  ml_tactic?: string;
  ml_confidence?: number;
  tags?: string[];
  published_at?: string;
  created_at: string;
  updated_at?: string;
}

export interface MetricsResponse {
  total_threats: number;
  active_incidents: number;
  blocked_attacks: number;
  affected_countries: number;
  daily_change?: {
    threats: number;
    incidents: number;
    blocked: number;
    countries: number;
  };
}

export interface SeverityStats {
  critical: number;
  high: number;
  medium: number;
  low: number;
  total?: number;
}

export interface IndicatorType {
  type: string;
  name?: string;
  count: number;
}

export interface TimelinePoint {
  date: string;
  name: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ThreatMapPoint {
  id: string;
  lat: number;
  lng: number;
  latitude?: number;
  longitude?: number;
  severity: Severity;
  type: string;
  description: string;
  count: number;
  country?: string;
  city?: string;
  attack_vector?: string;
}

export interface DashboardData {
  metrics: MetricsResponse;
  severity_stats: SeverityStats;
  indicator_types: IndicatorType[];
  recent_alerts: Alert[];
  latest_alerts?: Alert[];
  trend_data?: TimelinePoint[];
  top_threats?: Array<{ title?: string; name?: string; severity: Severity; count: number; trend?: 'up' | 'down' }>;
  top_countries?: Array<Record<string, any>>;
  map_points?: ThreatMapPoint[];
  attack_vectors?: Array<{ vector: string; value: number; count?: number }>;
  mitre_coverage?: Array<Record<string, any>>;
  ml_summary?: Record<string, any>;
}

export interface AnalyticsSummary {
  timeline: TimelinePoint[];
  severity_heatmap: Array<Record<string, any>>;
  feed_severity: Array<Record<string, any>>;
  top_countries: Array<Record<string, any>>;
  map_points: ThreatMapPoint[];
  attack_vectors: Array<{ vector: string; value: number; count?: number }>;
  mitre_coverage: Array<Record<string, any>>;
  severity_stats: SeverityStats;
  indicator_types: IndicatorType[];
  ml_summary: Record<string, any>;
}

function normalizeFeed(raw: any): Feed {
  return {
    ...raw,
    source_url: raw.source_url || raw.url || '',
    url: raw.url || raw.source_url || '',
    source: raw.source || 'API',
    status: raw.status || (raw.enabled === false ? 'inactive' : 'active'),
    enabled: raw.enabled ?? raw.status !== 'inactive',
    last_updated: raw.last_updated || raw.last_fetched_at,
  };
}

function normalizeAlert(raw: any): Alert {
  const severity: Severity = raw.severity || 'medium';
  const risk = raw.risk_score ?? 50;
  const status: ThreatStatus = raw.status || (severity === 'critical' || risk >= 80 ? 'active' : severity === 'high' ? 'investigating' : 'mitigated');
  const type = raw.type || raw.indicator_type || 'indicator';
  return {
    ...raw,
    description: raw.description || '',
    indicator_type: raw.indicator_type || type,
    indicator_value: raw.indicator_value || raw.indicator || '',
    indicator: raw.indicator || raw.indicator_value,
    severity,
    type,
    status,
    source: raw.source || raw.feed_name || 'Unknown',
    feed_name: raw.feed_name || raw.source,
    lat: raw.lat ?? raw.latitude,
    lng: raw.lng ?? raw.longitude,
    created_at: raw.created_at || raw.published_at || new Date().toISOString(),
  };
}

const fallbackDashboard: DashboardData = {
  metrics: { total_threats: 916, active_incidents: 243, blocked_attacks: 673, affected_countries: 15 },
  severity_stats: { critical: 85, high: 210, medium: 398, low: 223, total: 916 },
  indicator_types: [
    { type: 'ip', count: 260 },
    { type: 'domain', count: 190 },
    { type: 'url', count: 165 },
    { type: 'hash', count: 130 },
    { type: 'cve', count: 95 },
    { type: 'file', count: 50 },
    { type: 'email', count: 26 },
  ],
  recent_alerts: [],
  trend_data: [],
};

// System APIs
export const systemAPI = {
  health: () => fetchAPI<Record<string, any>>('/health', undefined, { status: 'offline-fallback' }),
  root: () => fetchAPI<Record<string, any>>('/', undefined, { message: 'ThreatShield API' }),
};

// Dashboard API
export const dashboardAPI = {
  getDashboard: async () => {
    const data = await fetchAPI<DashboardData>('/api/v1/dashboard', undefined, fallbackDashboard);
    return {
      ...fallbackDashboard,
      ...data,
      recent_alerts: (data.recent_alerts || data.latest_alerts || []).map(normalizeAlert),
      indicator_types: data.indicator_types || fallbackDashboard.indicator_types,
      trend_data: data.trend_data || fallbackDashboard.trend_data,
    };
  },
};

// Feeds APIs
export const feedsAPI = {
  list: async (params?: { skip?: number; limit?: number; status?: string; q?: string }) => {
    const data = await fetchAPI<any[]>(`/api/v1/feeds${buildQuery(params)}`, undefined, []);
    return data.map(normalizeFeed);
  },
  get: async (feedId: string) => normalizeFeed(await fetchAPI<any>(`/api/v1/feeds/${feedId}`)),
  create: async (feed: Partial<Feed> & { type?: string }) => {
    const payload = {
      name: feed.name,
      source_url: feed.source_url || feed.url,
      source: feed.source || feed.type || 'API',
      description: feed.description,
      enabled: feed.enabled ?? true,
    };
    return normalizeFeed(await fetchAPI<any>('/api/v1/feeds', { method: 'POST', body: JSON.stringify(payload) }));
  },
  update: async (feedId: string, feed: Partial<Feed> & { type?: string }) => {
    const payload = {
      ...feed,
      source_url: feed.source_url || feed.url,
      source: feed.source || feed.type,
    };
    return normalizeFeed(await fetchAPI<any>(`/api/v1/feeds/${feedId}`, { method: 'PATCH', body: JSON.stringify(payload) }));
  },
  delete: (feedId: string) => fetchAPI<void>(`/api/v1/feeds/${feedId}`, { method: 'DELETE' }),
};

// Alerts APIs
export const alertsAPI = {
  list: async (params?: { skip?: number; limit?: number; severity?: string; indicator_type?: string; feed_id?: string; status?: string; q?: string }) => {
    const data = await fetchAPI<any[]>(`/api/v1/alerts${buildQuery(params)}`, undefined, []);
    return data.map(normalizeAlert);
  },
  get: async (alertId: string) => normalizeAlert(await fetchAPI<any>(`/api/v1/alerts/${alertId}`)),
  create: async (alert: Partial<Alert>) => normalizeAlert(await fetchAPI<any>('/api/v1/alerts', { method: 'POST', body: JSON.stringify(alert) })),
  update: async (alertId: string, alert: Partial<Alert>) => normalizeAlert(await fetchAPI<any>(`/api/v1/alerts/${alertId}`, { method: 'PATCH', body: JSON.stringify(alert) })),
  delete: (alertId: string) => fetchAPI<void>(`/api/v1/alerts/${alertId}`, { method: 'DELETE' }),
};

// Stats, analytics and map APIs
export const statsAPI = {
  metrics: () => fetchAPI<MetricsResponse>('/api/v1/metrics', undefined, fallbackDashboard.metrics),
  severity: () => fetchAPI<SeverityStats>('/api/v1/stats/severity', undefined, fallbackDashboard.severity_stats),
  indicatorTypes: () => fetchAPI<IndicatorType[]>('/api/v1/stats/indicator-types', undefined, fallbackDashboard.indicator_types),
  timeline: (days = 14) => fetchAPI<TimelinePoint[]>(`/api/v1/stats/timeline?days=${days}`, undefined, []),
  heatmap: () => fetchAPI<Array<Record<string, any>>>('/api/v1/stats/heatmap', undefined, []),
  feedSeverity: () => fetchAPI<Array<Record<string, any>>>('/api/v1/stats/feed-severity', undefined, []),
  countries: () => fetchAPI<Array<Record<string, any>>>('/api/v1/stats/countries', undefined, []),
  attackVectors: () => fetchAPI<Array<{ vector: string; value: number }>>('/api/v1/stats/attack-vectors', undefined, []),
};

export const analyticsAPI = {
  summary: () => fetchAPI<AnalyticsSummary>('/api/v1/analytics/summary', undefined, {
    timeline: [], severity_heatmap: [], feed_severity: [], top_countries: [], map_points: [], attack_vectors: [], mitre_coverage: [],
    severity_stats: fallbackDashboard.severity_stats, indicator_types: fallbackDashboard.indicator_types, ml_summary: {},
  }),
};

export const mapAPI = {
  threats: (limit = 250) => fetchAPI<ThreatMapPoint[]>(`/api/v1/map/threats?limit=${limit}`, undefined, []),
};

export const collectorAPI = {
  status: () => fetchAPI<Record<string, any>>('/api/v1/collector/status', undefined, { running: false, collectors: [] }),
  trigger: () => fetchAPI<Record<string, any>>('/api/v1/collector/trigger', { method: 'POST' }),
  history: () => fetchAPI<Array<Record<string, any>>>('/api/v1/collector/history', undefined, []),
};

export const mlAPI = {
  status: () => fetchAPI<Record<string, any>>('/api/v1/ml/status', undefined, {}),
  train: () => fetchAPI<Record<string, any>>('/api/v1/ml/train', { method: 'POST' }),
  predict: (payload: Record<string, any>) => fetchAPI<Record<string, any>>('/api/v1/ml/predict', { method: 'POST', body: JSON.stringify(payload) }),
  evaluate: () => fetchAPI<Record<string, any>>('/api/v1/ml/evaluate', undefined, {}),
};

export const pipelineAPI = {
  enrich: (target: string) => fetchAPI<Record<string, any>>(`/api/v1/pipeline/enrich/${encodeURIComponent(target)}`, { method: 'POST' }),
};

export const telegramAPI = {
  test: (message?: string) => fetchAPI<Record<string, any>>('/api/v1/telegram/test', { method: 'POST', body: JSON.stringify({ message }) }),
};

// Debug APIs
export const debugAPI = {
  ingestMock: () => fetchAPI<Record<string, any>>('/api/v1/ingest/mock', { method: 'POST' }),
  resetDatabase: () => fetchAPI<Record<string, any>>('/api/v1/reset', { method: 'POST' }),
};

export const api = {
  system: systemAPI,
  dashboard: dashboardAPI,
  feeds: feedsAPI,
  alerts: alertsAPI,
  stats: statsAPI,
  analytics: analyticsAPI,
  map: mapAPI,
  collector: collectorAPI,
  ml: mlAPI,
  pipeline: pipelineAPI,
  telegram: telegramAPI,
  debug: debugAPI,
};
