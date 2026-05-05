import { StatCard } from '../components/stat-card';
import { Card } from '../components/ui/card';
import { AlertTriangle, Shield, Activity, Globe, TrendingUp, TrendingDown } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { useAPI } from '../hooks/use-api';
import { api } from '../services/api';

const threatTrendData = [
  { name: 'Mon', total: 120 },
  { name: 'Tue', total: 137 },
  { name: 'Wed', total: 138 },
  { name: 'Thu', total: 159 },
  { name: 'Fri', total: 160 },
  { name: 'Sat', total: 100 },
  { name: 'Sun', total: 112 },
];

export function OverviewPage() {
  // Fetch data from API
  const { data: dashboardData, loading, error } = useAPI(() => api.dashboard.getDashboard(), []);
  const { data: severityData } = useAPI(() => api.stats.severity(), []);
  const { data: indicatorTypes } = useAPI(() => api.stats.indicatorTypes(), []);

  // Loading state
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-600">Đang tải dữ liệu...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Card className="p-6 max-w-md">
          <div className="text-center">
            <AlertTriangle className="w-12 h-12 text-red-600 mx-auto mb-3" />
            <h3 className="text-lg font-semibold mb-2">Lỗi kết nối API</h3>
            <p className="text-gray-600 text-sm mb-4">{error.message}</p>
            <p className="text-xs text-gray-500">Đang sử dụng dữ liệu mẫu</p>
          </div>
        </Card>
      </div>
    );
  }

  // Map API data to display format
  const metrics = dashboardData?.metrics || {
    total_threats: 926,
    active_incidents: 23,
    blocked_attacks: 1847,
    affected_countries: 47
  };

  const threatTypeData = indicatorTypes?.map((item, index) => ({
    name: item.type,
    value: item.count,
    color: ['#ef4444', '#f97316', '#f59e0b', '#eab308'][index % 4]
  })) || [
    { name: 'Malware', value: 341, color: '#ef4444' },
    { name: 'Phishing', value: 253, color: '#f97316' },
    { name: 'DDoS', value: 197, color: '#f59e0b' },
    { name: 'Breach', value: 135, color: '#eab308' },
  ];

  const topThreats = dashboardData?.recent_alerts?.slice(0, 5).map(alert => ({
    name: alert.title,
    severity: alert.severity,
    count: Math.floor(Math.random() * 50) + 10,
    trend: Math.random() > 0.5 ? 'up' : 'down'
  })) || [
    { name: 'CVE-2024-1234', severity: 'critical', count: 45, trend: 'up' },
    { name: 'Phishing Campaign XYZ', severity: 'high', count: 38, trend: 'up' },
    { name: 'Malware.Gen.Variant', severity: 'high', count: 32, trend: 'down' },
    { name: 'DDoS Botnet Alpha', severity: 'medium', count: 28, trend: 'up' },
    { name: 'SQL Injection Attempts', severity: 'medium', count: 25, trend: 'down' },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Tổng quan</h2>
        <p className="text-gray-600 mt-1">Thống kê và xu hướng mối đe dọa</p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Tổng mối đe dọa"
          value={metrics.total_threats.toString()}
          change="+12.5% từ hôm qua"
          changeType="increase"
          icon={AlertTriangle}
          iconColor="text-red-600"
          iconBg="bg-red-100"
        />
        <StatCard
          title="Sự cố đang hoạt động"
          value={metrics.active_incidents.toString()}
          change="-8.3% từ hôm qua"
          changeType="decrease"
          icon={Activity}
          iconColor="text-orange-600"
          iconBg="bg-orange-100"
        />
        <StatCard
          title="Tấn công đã chặn"
          value={metrics.blocked_attacks.toLocaleString()}
          change="+15.2% từ hôm qua"
          changeType="increase"
          icon={Shield}
          iconColor="text-blue-600"
          iconBg="bg-blue-100"
        />
        <StatCard
          title="Quốc gia bị ảnh hưởng"
          value={metrics.affected_countries.toString()}
          change="+3 mới"
          changeType="increase"
          icon={Globe}
          iconColor="text-purple-600"
          iconBg="bg-purple-100"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Xu hướng 7 ngày</h3>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={threatTrendData}>
              <defs>
                <linearGradient id="colorTotal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                  <stop offset="95%" stopColor="#3b82f6" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Area type="monotone" dataKey="total" stroke="#3b82f6" fillOpacity={1} fill="url(#colorTotal)" />
            </AreaChart>
          </ResponsiveContainer>
        </Card>

        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Phân loại mối đe dọa</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={threatTypeData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {threatTypeData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Top Threats Table */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Top mối đe dọa hàng đầu</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-medium text-gray-600">Tên</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Mức độ</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Số lượng</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Xu hướng</th>
              </tr>
            </thead>
            <tbody>
              {topThreats.map((threat, index) => (
                <tr key={index} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4 font-medium">{threat.name}</td>
                  <td className="py-3 px-4">
                    <span className={`text-xs px-2 py-1 rounded ${
                      threat.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      threat.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      'bg-yellow-100 text-yellow-800'
                    }`}>
                      {threat.severity}
                    </span>
                  </td>
                  <td className="py-3 px-4">{threat.count}</td>
                  <td className="py-3 px-4">
                    {threat.trend === 'up' ? (
                      <TrendingUp className="w-5 h-5 text-red-600" />
                    ) : (
                      <TrendingDown className="w-5 h-5 text-green-600" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}