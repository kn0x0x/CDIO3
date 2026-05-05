import { useState } from 'react';
import { Card } from '../components/ui/card';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Button } from '../components/ui/button';
import { Search, Filter, Download, Eye, RefreshCw } from 'lucide-react';
import { useAPI } from '../hooks/use-api';
import { api, Alert } from '../services/api';
import { ExportMenu } from '../components/export-menu';

interface Threat {
  id: string;
  name: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'active' | 'mitigated' | 'investigating';
  firstSeen: string;
  lastSeen: string;
  count: number;
  source: string;
}

const threats: Threat[] = [
  { id: '1', name: 'CVE-2024-1234', type: 'Vulnerability', severity: 'critical', status: 'active', firstSeen: '2024-04-12', lastSeen: '2 phút trước', count: 145, source: 'Multiple' },
  { id: '2', name: 'Phishing Campaign Alpha', type: 'Phishing', severity: 'high', status: 'investigating', firstSeen: '2024-04-13', lastSeen: '15 phút trước', count: 89, source: 'Email' },
  { id: '3', name: 'Malware.Gen.Variant.X', type: 'Malware', severity: 'high', status: 'active', firstSeen: '2024-04-10', lastSeen: '1 giờ trước', count: 203, source: 'Endpoint' },
  { id: '4', name: 'DDoS Botnet Beta', type: 'DDoS', severity: 'medium', status: 'mitigated', firstSeen: '2024-04-11', lastSeen: '3 giờ trước', count: 67, source: 'Network' },
  { id: '5', name: 'SQL Injection Attempt', type: 'Web Attack', severity: 'high', status: 'active', firstSeen: '2024-04-14', lastSeen: '30 phút trước', count: 124, source: 'Web' },
  { id: '6', name: 'Ransomware Gamma', type: 'Ransomware', severity: 'critical', status: 'investigating', firstSeen: '2024-04-12', lastSeen: '45 phút trước', count: 56, source: 'Endpoint' },
  { id: '7', name: 'Crypto Mining Activity', type: 'Malware', severity: 'medium', status: 'mitigated', firstSeen: '2024-04-09', lastSeen: '5 giờ trước', count: 38, source: 'Cloud' },
  { id: '8', name: 'Port Scanning Campaign', type: 'Reconnaissance', severity: 'low', status: 'active', firstSeen: '2024-04-13', lastSeen: '2 giờ trước', count: 412, source: 'Network' },
  { id: '9', name: 'Brute Force Attack', type: 'Authentication', severity: 'high', status: 'active', firstSeen: '2024-04-14', lastSeen: '20 phút trước', count: 287, source: 'Multiple' },
  { id: '10', name: 'Suspicious Data Exfiltration', type: 'Data Breach', severity: 'critical', status: 'investigating', firstSeen: '2024-04-15', lastSeen: '10 phút trước', count: 23, source: 'Network' },
];

export function ThreatsPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');

  // Fetch alerts from API
  const { data: alerts, loading, error, refetch } = useAPI(() => api.alerts.list(), []);

  const filteredThreats = (alerts || []).filter(alert => {
    const matchesSearch = alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          alert.type.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = filterSeverity === 'all' || alert.severity === filterSeverity;
    return matchesSearch && matchesSeverity;
  });

  // Loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-600">Đang tải dữ liệu mối đe dọa...</p>
        </div>
      </div>
    );
  }

  const threatList = alerts || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Danh sách mối đe dọa</h2>
          <p className="text-gray-600 mt-1">Quản lý và theo dõi tất cả các mối đe dọa</p>
        </div>
        <Button onClick={refetch} variant="outline">
          <RefreshCw className="w-4 h-4 mr-2" />
          Làm mới
        </Button>
      </div>

      {error && (
        <Card className="p-4 bg-yellow-50 border-yellow-200">
          <p className="text-sm text-yellow-800">⚠️ Không thể kết nối API: {error.message}</p>
        </Card>
      )}

      {/* Filters */}
      <Card className="p-4">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <Input
                type="text"
                placeholder="Tìm kiếm mối đe dọa..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="pl-10"
              />
            </div>
          </div>
          <div className="flex gap-2">
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="all">Tất cả mức độ</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <Button variant="outline">
              <Filter className="w-4 h-4 mr-2" />
              Bộ lọc
            </Button>
            <ExportMenu data={filteredThreats} filename="threats-report" />
          </div>
        </div>
      </Card>

      {/* Threats Table */}
      <Card className="p-6">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-medium text-gray-600">Tên mối đe dọa</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Loại</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Mức độ</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Trạng thái</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Nguồn</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Thời gian</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Hành động</th>
              </tr>
            </thead>
            <tbody>
              {filteredThreats.map((threat) => (
                <tr key={threat.id} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4">
                    <div>
                      <p className="font-medium">{threat.title}</p>
                      <p className="text-xs text-gray-500">{threat.description}</p>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">{threat.type}</td>
                  <td className="py-3 px-4">
                    <Badge variant={
                      threat.severity === 'critical' ? 'destructive' :
                      threat.severity === 'high' ? 'default' :
                      'secondary'
                    }>
                      {threat.severity}
                    </Badge>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`text-xs px-2 py-1 rounded ${
                      threat.status === 'active' ? 'bg-red-100 text-red-800' :
                      threat.status === 'investigating' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-green-100 text-green-800'
                    }`}>
                      {threat.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-sm text-gray-600">{threat.source || '-'}</td>
                  <td className="py-3 px-4 text-sm text-gray-600">
                    {new Date(threat.created_at).toLocaleString('vi-VN')}
                  </td>
                  <td className="py-3 px-4">
                    <Button variant="ghost" size="sm">
                      <Eye className="w-4 h-4" />
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {filteredThreats.length === 0 && (
          <div className="text-center py-8 text-gray-500">
            Không tìm thấy mối đe dọa nào
          </div>
        )}
      </Card>

      {/* Summary */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-sm text-gray-600">Tổng mối đe dọa</p>
          <p className="text-2xl font-bold mt-1">{threatList.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Đang hoạt động</p>
          <p className="text-2xl font-bold mt-1 text-red-600">
            {threatList.filter(t => t.status === 'active').length}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Đang điều tra</p>
          <p className="text-2xl font-bold mt-1 text-yellow-600">
            {threatList.filter(t => t.status === 'investigating').length}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Đã xử lý</p>
          <p className="text-2xl font-bold mt-1 text-green-600">
            {threatList.filter(t => t.status === 'mitigated').length}
          </p>
        </Card>
      </div>
    </div>
  );
}