import { Card } from '../components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs';
import { BarChart, Bar, LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar } from 'recharts';
import { useAPI } from '../hooks/use-api';
import { api } from '../services/api';

const fallbackTimeline = [
  { name: 'D-6', total: 120, critical: 12, high: 34, medium: 48, low: 26 },
  { name: 'D-5', total: 137, critical: 15, high: 38, medium: 52, low: 32 },
  { name: 'D-4', total: 138, critical: 11, high: 40, medium: 60, low: 27 },
  { name: 'D-3', total: 159, critical: 22, high: 44, medium: 62, low: 31 },
  { name: 'D-2', total: 160, critical: 18, high: 45, medium: 67, low: 30 },
  { name: 'D-1', total: 100, critical: 9, high: 24, medium: 45, low: 22 },
  { name: 'Today', total: 112, critical: 14, high: 29, medium: 48, low: 21 },
];

export function AnalyticsPage() {
  const { data: analytics, loading, error } = useAPI(() => api.analytics.summary(), []);

  const timeline = analytics?.timeline?.length ? analytics.timeline : fallbackTimeline;
  const heatmap = analytics?.severity_heatmap?.length ? analytics.severity_heatmap : [];
  const feedSeverity = analytics?.feed_severity?.length ? analytics.feed_severity : [];
  const attackVectors = analytics?.attack_vectors?.length ? analytics.attack_vectors : [
    { vector: 'Email', value: 65 }, { vector: 'Web', value: 82 }, { vector: 'Network', value: 73 }, { vector: 'Endpoint', value: 58 }, { vector: 'Cloud', value: 45 }, { vector: 'Identity', value: 38 },
  ];
  const mitreCoverage = analytics?.mitre_coverage?.length ? analytics.mitre_coverage : [];
  const ml = analytics?.ml_summary || {};

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="mt-4 text-gray-600">Đang tải phân tích dữ liệu...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Phân tích chi tiết + ML</h2>
        <p className="text-gray-600 mt-1">Heatmap IoC, feed × severity, MITRE ATT&CK và đánh giá mô hình scikit-learn</p>
      </div>

      {error && (
        <Card className="p-4 bg-yellow-50 border-yellow-200">
          <p className="text-sm text-yellow-800">⚠️ Không thể kết nối API phân tích: {error.message}</p>
        </Card>
      )}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-sm text-gray-600">ML accuracy</p>
          <p className="text-2xl font-bold mt-1">{ml.accuracy !== undefined ? `${(ml.accuracy * 100).toFixed(1)}%` : 'N/A'}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Macro F1</p>
          <p className="text-2xl font-bold mt-1">{ml.macro_f1 !== undefined ? `${(ml.macro_f1 * 100).toFixed(1)}%` : 'N/A'}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Train/Test</p>
          <p className="text-2xl font-bold mt-1">{ml.train_size || 0}/{ml.test_size || 0}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Tactic labels</p>
          <p className="text-2xl font-bold mt-1">{ml.labels?.length || 0}</p>
        </Card>
      </div>

      <Tabs defaultValue="trends" className="w-full">
        <TabsList className="flex flex-wrap h-auto">
          <TabsTrigger value="trends">Timeline</TabsTrigger>
          <TabsTrigger value="heatmap">IoC × Severity</TabsTrigger>
          <TabsTrigger value="feeds">Nguồn × Severity</TabsTrigger>
          <TabsTrigger value="vectors">Vector tấn công</TabsTrigger>
          <TabsTrigger value="mitre">MITRE + ML</TabsTrigger>
        </TabsList>

        <TabsContent value="trends" className="space-y-6 mt-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Timeline ingest IoC theo ngày</h3>
            <ResponsiveContainer width="100%" height={360}>
              <AreaChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" fill="#dc2626" name="Critical" />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#ea580c" fill="#ea580c" name="High" />
                <Area type="monotone" dataKey="medium" stackId="1" stroke="#f59e0b" fill="#f59e0b" name="Medium" />
                <Area type="monotone" dataKey="low" stackId="1" stroke="#84cc16" fill="#84cc16" name="Low" />
              </AreaChart>
            </ResponsiveContainer>
          </Card>

          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Tổng IoC và critical theo thời gian</h3>
            <ResponsiveContainer width="100%" height={320}>
              <LineChart data={timeline}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Line type="monotone" dataKey="total" stroke="#2563eb" strokeWidth={3} name="Tổng IoC" />
                <Line type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={2} name="Critical" />
              </LineChart>
            </ResponsiveContainer>
          </Card>
        </TabsContent>

        <TabsContent value="heatmap" className="mt-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Heatmap IoC theo indicator_type × severity</h3>
            <ResponsiveContainer width="100%" height={420}>
              <BarChart data={heatmap}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="indicator_type" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="critical" stackId="a" fill="#dc2626" name="Critical" />
                <Bar dataKey="high" stackId="a" fill="#ea580c" name="High" />
                <Bar dataKey="medium" stackId="a" fill="#f59e0b" name="Medium" />
                <Bar dataKey="low" stackId="a" fill="#84cc16" name="Low" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </TabsContent>

        <TabsContent value="feeds" className="mt-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Stacked bar IoC theo feed × severity</h3>
            <ResponsiveContainer width="100%" height={420}>
              <BarChart data={feedSeverity} layout="vertical" margin={{ left: 80 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="feed" type="category" width={140} />
                <Tooltip />
                <Legend />
                <Bar dataKey="critical" stackId="a" fill="#dc2626" name="Critical" />
                <Bar dataKey="high" stackId="a" fill="#ea580c" name="High" />
                <Bar dataKey="medium" stackId="a" fill="#f59e0b" name="Medium" />
                <Bar dataKey="low" stackId="a" fill="#84cc16" name="Low" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </TabsContent>

        <TabsContent value="vectors" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Vector tấn công</h3>
              <ResponsiveContainer width="100%" height={400}>
                <RadarChart data={attackVectors}>
                  <PolarGrid />
                  <PolarAngleAxis dataKey="vector" />
                  <PolarRadiusAxis />
                  <Radar name="IoC" dataKey="value" stroke="#2563eb" fill="#2563eb" fillOpacity={0.5} />
                  <Tooltip />
                </RadarChart>
              </ResponsiveContainer>
            </Card>

            <Card className="p-6">
              <h3 className="text-lg font-semibold mb-4">Thống kê vector</h3>
              <ResponsiveContainer width="100%" height={400}>
                <BarChart data={attackVectors}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="vector" />
                  <YAxis />
                  <Tooltip />
                  <Bar dataKey="value" fill="#2563eb" />
                </BarChart>
              </ResponsiveContainer>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="mitre" className="mt-6 space-y-6">
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">So sánh độ phủ tactic Rule-based vs ML model</h3>
            <ResponsiveContainer width="100%" height={420}>
              <BarChart data={mitreCoverage} layout="vertical" margin={{ left: 110 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" />
                <YAxis dataKey="tactic" type="category" width={160} />
                <Tooltip />
                <Legend />
                <Bar dataKey="rule_based" fill="#7c3aed" name="Rule-based" />
                <Bar dataKey="ml_model" fill="#06b6d4" name="ML match" />
              </BarChart>
            </ResponsiveContainer>
          </Card>

          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Confusion matrix per tactic</h3>
            {ml.confusion_matrix && ml.labels ? (
              <div className="overflow-x-auto">
                <table className="text-sm border-collapse">
                  <thead>
                    <tr>
                      <th className="border px-2 py-1 bg-gray-50">Actual \ Pred</th>
                      {ml.labels.map((label: string) => <th key={label} className="border px-2 py-1 bg-gray-50 whitespace-nowrap">{label}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {ml.confusion_matrix.map((row: number[], i: number) => (
                      <tr key={ml.labels[i]}>
                        <td className="border px-2 py-1 font-medium bg-gray-50 whitespace-nowrap">{ml.labels[i]}</td>
                        {row.map((value, j) => <td key={j} className="border px-2 py-1 text-center">{value}</td>)}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500">Chưa có dữ liệu đánh giá mô hình.</p>
            )}
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
