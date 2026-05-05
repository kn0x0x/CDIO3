/**
 * Backend API Service - Tích hợp với FastAPI backend
 * Base URL: http://localhost:8000
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface APIResponse<T = any> {
  success: boolean;
  message: string;
  data: T;
  meta?: Record<string, any>;
}

class BackendAPI {
  private baseURL: string;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.baseURL}${endpoint}`;

    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({
        success: false,
        message: `HTTP ${response.status}: ${response.statusText}`,
      }));
      throw new Error(error.message || 'API request failed');
    }

    const result: APIResponse<T> = await response.json();

    if (!result.success) {
      throw new Error(result.message || 'Request failed');
    }

    return result.data;
  }

  // ============================================================================
  // Dashboard
  // ============================================================================
  async getDashboard() {
    return this.request('/api/v1/dashboard');
  }

  // ============================================================================
  // Feeds
  // ============================================================================
  async getFeeds(params?: {
    skip?: number;
    limit?: number;
    status?: 'active' | 'inactive';
    q?: string;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.skip) queryParams.append('skip', params.skip.toString());
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.status) queryParams.append('status', params.status);
    if (params?.q) queryParams.append('q', params.q);

    const query = queryParams.toString();
    return this.request(`/api/v1/feeds${query ? `?${query}` : ''}`);
  }

  async getFeed(feedId: string) {
    return this.request(`/api/v1/feeds/${feedId}`);
  }

  async createFeed(data: {
    name: string;
    source_url: string;
    description?: string;
  }) {
    return this.request('/api/v1/feeds', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateFeed(feedId: string, data: {
    name?: string;
    source_url?: string;
    description?: string;
    status?: 'active' | 'inactive';
  }) {
    return this.request(`/api/v1/feeds/${feedId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteFeed(feedId: string) {
    return this.request(`/api/v1/feeds/${feedId}`, {
      method: 'DELETE',
    });
  }

  // ============================================================================
  // Alerts
  // ============================================================================
  async getAlerts(params?: {
    skip?: number;
    limit?: number;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    indicator_type?: string;
    feed_id?: string;
    q?: string;
  }) {
    const queryParams = new URLSearchParams();
    if (params?.skip) queryParams.append('skip', params.skip.toString());
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    if (params?.severity) queryParams.append('severity', params.severity);
    if (params?.indicator_type) queryParams.append('indicator_type', params.indicator_type);
    if (params?.feed_id) queryParams.append('feed_id', params.feed_id);
    if (params?.q) queryParams.append('q', params.q);

    const query = queryParams.toString();
    return this.request(`/api/v1/alerts${query ? `?${query}` : ''}`);
  }

  async getAlert(alertId: string) {
    return this.request(`/api/v1/alerts/${alertId}`);
  }

  async createAlert(data: {
    feed_id: string;
    title: string;
    description?: string;
    indicator_type: 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'cve' | 'file';
    indicator_value: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    confidence?: number;
    tags?: string[];
  }) {
    return this.request('/api/v1/alerts', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateAlert(alertId: string, data: {
    title?: string;
    description?: string;
    severity?: 'low' | 'medium' | 'high' | 'critical';
    confidence?: number;
    tags?: string[];
  }) {
    return this.request(`/api/v1/alerts/${alertId}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteAlert(alertId: string) {
    return this.request(`/api/v1/alerts/${alertId}`, {
      method: 'DELETE',
    });
  }

  // ============================================================================
  // Stats & Metrics
  // ============================================================================
  async getMetrics() {
    return this.request('/api/v1/metrics');
  }

  async getSeverityStats() {
    return this.request('/api/v1/stats/severity');
  }

  async getIndicatorTypeStats() {
    return this.request('/api/v1/stats/indicator-types');
  }

  // ============================================================================
  // Collector
  // ============================================================================
  async getCollectorStatus() {
    return this.request('/api/v1/collector/status');
  }

  async triggerCollector() {
    return this.request('/api/v1/collector/trigger', {
      method: 'POST',
    });
  }

  async getCollectorHistory() {
    return this.request('/api/v1/collector/history');
  }

  // ============================================================================
  // Debug
  // ============================================================================
  async mockIngest() {
    return this.request('/api/v1/ingest/mock', {
      method: 'POST',
    });
  }

  async resetDatabase() {
    return this.request('/api/v1/reset', {
      method: 'POST',
    });
  }

  // ============================================================================
  // Health
  // ============================================================================
  async healthCheck() {
    return this.request('/health');
  }
}

export const backendAPI = new BackendAPI();
