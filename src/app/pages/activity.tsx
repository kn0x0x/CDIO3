import { Card } from '../components/ui/card';
import { ThreatTimeline, ThreatEvent } from '../components/threat-timeline';
import { Badge } from '../components/ui/badge';
import { Clock, Activity as ActivityIcon, CheckCircle, XCircle } from 'lucide-react';
import { useAPI } from '../hooks/use-api';
import { api } from '../services/api';

const systemActivities = [
  { id: '1', action: 'Cập nhật quy tắc tường lửa', user: 'Admin', time: '10 phút trước', status: 'success' },
  { id: '2', action: 'Quét bảo mật hệ thống', user: 'System', time: '25 phút trước', status: 'success' },
  { id: '3', action: 'Cập nhật chữ ký Malware', user: 'System', time: '1 giờ trước', status: 'success' },
  { id: '4', action: 'Sao lưu cơ sở dữ liệu', user: 'System', time: '2 giờ trước', status: 'success' },
  { id: '5', action: 'Thử kết nối API thất bại', user: 'Integration', time: '3 giờ trước', status: 'failed' },
  { id: '6', action: 'Cấu hình IDS/IPS', user: 'Admin', time: '4 giờ trước', status: 'success' },
];

export function ActivityPage() {
  // Fetch alerts from API
  const { data: alerts, loading } = useAPI(() => api.alerts.list(), []);

  // Map alerts to timeline events
  const threatEvents: ThreatEvent[] = (alerts || []).slice(0, 10).map((alert, index) => {
    const timeAgo = Math.floor((Date.now() - new Date(alert.created_at).getTime()) / 60000);
    const timeStr = timeAgo < 60 ? `${timeAgo} phút trước` : `${Math.floor(timeAgo / 60)} giờ trước`;
    
    // Map alert type to event type
    let eventType: 'breach' | 'malware' | 'phishing' | 'ddos' = 'malware';
    if (alert.type.toLowerCase().includes('breach') || alert.type.toLowerCase().includes('unauthorized')) {
      eventType = 'breach';
    } else if (alert.type.toLowerCase().includes('phishing')) {
      eventType = 'phishing';
    } else if (alert.type.toLowerCase().includes('ddos')) {
      eventType = 'ddos';
    }

    return {
      id: alert.id,
      time: timeStr,
      type: eventType,
      title: alert.title,
      description: alert.description,
      severity: alert.severity
    };
  });

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-600">Đang tải hoạt động...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Hoạt động thời gian thực</h2>
        <p className="text-gray-600 mt-1">Theo dõi các sự kiện và hoạt động hệ thống</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <ActivityIcon className="w-5 h-5 text-blue-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Sự kiện hôm nay</p>
              <p className="text-xl font-bold">{alerts?.length || 0}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-red-100 rounded-lg">
              <XCircle className="w-5 h-5 text-red-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Cảnh báo</p>
              <p className="text-xl font-bold">
                {alerts?.filter(a => a.severity === 'critical' || a.severity === 'high').length || 0}
              </p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="w-5 h-5 text-green-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Đã xử lý</p>
              <p className="text-xl font-bold">
                {alerts?.filter(a => a.status === 'mitigated').length || 0}
              </p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="w-5 h-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-sm text-gray-600">Đang chờ</p>
              <p className="text-xl font-bold">
                {alerts?.filter(a => a.status === 'active' || a.status === 'investigating').length || 0}
              </p>
            </div>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Timeline */}
        <div>
          <ThreatTimeline events={threatEvents} />
        </div>

        {/* System Activity */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Hoạt động hệ thống</h3>
          <div className="space-y-3 max-h-96 overflow-y-auto">
            {systemActivities.map((activity) => (
              <div key={activity.id} className="flex items-start gap-3 pb-3 border-b last:border-0">
                <div className={`p-2 rounded-lg ${
                  activity.status === 'success' ? 'bg-green-100' : 'bg-red-100'
                }`}>
                  {activity.status === 'success' ? (
                    <CheckCircle className="w-4 h-4 text-green-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-600" />
                  )}
                </div>
                <div className="flex-1">
                  <div className="flex items-start justify-between">
                    <h4 className="font-medium text-sm">{activity.action}</h4>
                    <span className="text-xs text-gray-500">{activity.time}</span>
                  </div>
                  <p className="text-sm text-gray-600 mt-1">Bởi: {activity.user}</p>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Alerts */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Cảnh báo và thông báo</h3>
        <div className="space-y-3">
          {alerts?.slice(0, 5).map((alert) => (
            <div key={alert.id} className="flex items-center gap-3 p-3 border border-gray-200 rounded-lg">
              <div className={`w-2 h-2 rounded-full ${
                alert.severity === 'critical' ? 'bg-red-600' :
                alert.severity === 'high' ? 'bg-orange-600' :
                alert.severity === 'medium' ? 'bg-yellow-600' :
                'bg-blue-600'
              }`}></div>
              <div className="flex-1">
                <p className="text-sm font-medium">{alert.title}</p>
              </div>
              <span className="text-xs text-gray-500">
                {new Date(alert.created_at).toLocaleTimeString('vi-VN')}
              </span>
              <Badge variant={
                alert.severity === 'critical' ? 'destructive' :
                alert.severity === 'high' ? 'default' :
                'secondary'
              }>
                {alert.severity}
              </Badge>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}