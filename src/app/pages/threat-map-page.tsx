import { Card } from '../components/ui/card';
import { ThreatMap, ThreatLocation } from '../components/threat-map';
import { Badge } from '../components/ui/badge';
import { useAPI } from '../hooks/use-api';
import { api } from '../services/api';

const fallbackThreatLocations: ThreatLocation[] = [
  { id: '1', lat: 37.7749, lng: -122.4194, severity: 'critical', type: 'DDoS Attack', description: 'Large-scale DDoS targeting infrastructure', count: 45 },
  { id: '2', lat: 51.5074, lng: -0.1278, severity: 'high', type: 'Phishing Campaign', description: 'Coordinated phishing attacks detected', count: 32 },
  { id: '3', lat: 35.6762, lng: 139.6503, severity: 'medium', type: 'Malware Detection', description: 'New malware variant identified', count: 28 },
  { id: '4', lat: 10.8231, lng: 106.6297, severity: 'critical', type: 'C2 Activity', description: 'Threat intelligence hits in Vietnam', count: 51 },
];

export function ThreatMapPage() {
  const { data: mapData, loading, error } = useAPI(() => api.map.threats(250), []);
  const { data: countries } = useAPI(() => api.stats.countries(), []);

  const threatLocations: ThreatLocation[] = (mapData && mapData.length > 0 ? mapData : fallbackThreatLocations).map((item: any) => ({
    id: item.id,
    lat: item.lat ?? item.latitude,
    lng: item.lng ?? item.longitude,
    severity: item.severity,
    type: item.type || item.indicator_type || item.attack_vector || 'IoC',
    description: item.description || `${item.count} IoC tại ${item.city || item.country || 'Unknown'}`,
    count: item.count || 1,
  }));

  const locationStats = (countries && countries.length > 0 ? countries : []).map((item: any) => ({
    region: item.country,
    threats: item.count,
    critical: item.critical || 0,
    high: item.high || 0,
    medium: Math.max(0, (item.count || 0) - (item.critical || 0) - (item.high || 0)),
    low: 0,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Bản đồ mối đe dọa toàn cầu</h2>
        <p className="text-gray-600 mt-1">Giám sát IoC đã enrichment theo vị trí địa lý</p>
      </div>

      {error && (
        <Card className="p-4 bg-yellow-50 border-yellow-200">
          <p className="text-sm text-yellow-800">⚠️ Không thể kết nối API bản đồ: {error.message}</p>
        </Card>
      )}

      <Card className="p-4">
        <div className="flex flex-wrap items-center gap-6">
          <span className="text-sm font-medium text-gray-700">Mức độ nghiêm trọng:</span>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded-full bg-red-600" /><span className="text-sm">Critical</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded-full bg-orange-600" /><span className="text-sm">High</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded-full bg-yellow-500" /><span className="text-sm">Medium</span></div>
          <div className="flex items-center gap-2"><div className="w-4 h-4 rounded-full bg-yellow-400" /><span className="text-sm">Low</span></div>
        </div>
      </Card>

      <Card className="p-6">
        {loading ? (
          <div className="h-[600px] flex items-center justify-center text-gray-500">Đang tải bản đồ...</div>
        ) : (
          <div className="h-[600px]">
            <ThreatMap threats={threatLocations} />
          </div>
        )}
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Top quốc gia chứa IoC</h3>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200">
                <th className="text-left py-3 px-4 font-medium text-gray-600">Quốc gia</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Tổng</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Critical</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">High</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600">Khác</th>
              </tr>
            </thead>
            <tbody>
              {locationStats.map((stat: any, index: number) => (
                <tr key={index} className="border-b border-gray-100 hover:bg-gray-50">
                  <td className="py-3 px-4 font-medium">{stat.region}</td>
                  <td className="py-3 px-4">{stat.threats}</td>
                  <td className="py-3 px-4"><Badge variant="destructive">{stat.critical}</Badge></td>
                  <td className="py-3 px-4"><span className="px-2 py-1 text-xs bg-orange-100 text-orange-800 rounded">{stat.high}</span></td>
                  <td className="py-3 px-4"><span className="px-2 py-1 text-xs bg-yellow-100 text-yellow-800 rounded">{stat.medium + stat.low}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
