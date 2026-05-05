import { useEffect, useState } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Settings as SettingsIcon, Database, Bell, Shield, Save, PlayCircle, Brain, Send, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import { toast } from 'sonner';

export function SettingsPage() {
  const [apiUrl, setApiUrl] = useState(import.meta.env.VITE_API_URL || 'http://localhost:8000');
  const [healthStatus, setHealthStatus] = useState<'checking' | 'healthy' | 'error'>('checking');
  const [healthData, setHealthData] = useState<Record<string, any> | null>(null);
  const [collector, setCollector] = useState<Record<string, any> | null>(null);
  const [ml, setMl] = useState<Record<string, any> | null>(null);
  const [saving, setSaving] = useState(false);

  const checkHealth = async () => {
    setHealthStatus('checking');
    try {
      const result = await api.system.health();
      setHealthData(result);
      setHealthStatus(result.status === 'ok' || result.status === 'offline-fallback' ? 'healthy' : 'error');
    } catch (error) {
      setHealthStatus('error');
    }
  };

  const loadStatus = async () => {
    try {
      const [collectorStatus, mlStatus] = await Promise.all([api.collector.status(), api.ml.status()]);
      setCollector(collectorStatus);
      setMl(mlStatus);
    } catch (error) {
      console.warn(error);
    }
  };

  useEffect(() => {
    checkHealth();
    loadStatus();
  }, []);

  const handleSave = async () => {
    setSaving(true);
    localStorage.setItem('threatshield_api_url_note', apiUrl);
    setTimeout(() => {
      setSaving(false);
      checkHealth();
      toast.success('Đã lưu cấu hình giao diện demo');
    }, 500);
  };

  const triggerCollector = async () => {
    try {
      const result = await api.collector.trigger();
      toast.success(result?.totals ? `Collector xong: ${result.totals.new} mới, ${result.totals.duplicates} trùng` : 'Collector đã chạy');
      await loadStatus();
    } catch (error: any) {
      toast.error(error.message || 'Không thể chạy collector');
    }
  };

  const trainModel = async () => {
    try {
      const result = await api.ml.train();
      setMl(result);
      toast.success(`Đã train ML: accuracy ${(result.accuracy * 100).toFixed(1)}%`);
    } catch (error: any) {
      toast.error(error.message || 'Không thể train ML');
    }
  };

  const testTelegram = async () => {
    try {
      const result = await api.telegram.test('✅ ThreatShield CDIO demo: Telegram alert test');
      toast.success(result.sent ? 'Đã gửi Telegram test' : result.reason || 'Telegram chưa cấu hình token/chat_id');
    } catch (error: any) {
      toast.error(error.message || 'Không thể gửi Telegram test');
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Cài đặt hệ thống</h2>
        <p className="text-gray-600 mt-1">Cấu hình kết nối API, collector, ML và Telegram alert</p>
      </div>

      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Database className="w-5 h-5 text-blue-600" />
          <h3 className="text-lg font-semibold">Cấu hình API Backend</h3>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">API Base URL</label>
            <Input type="text" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} placeholder="http://localhost:8000" />
            <p className="text-xs text-gray-500 mt-1">Đặt VITE_API_URL trong file .env để đổi URL thật khi build.</p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={checkHealth} variant="outline"><RefreshCw className="w-4 h-4 mr-2" />Kiểm tra kết nối</Button>
            <Badge variant={healthStatus === 'healthy' ? 'default' : healthStatus === 'error' ? 'destructive' : 'secondary'}>
              {healthStatus === 'healthy' ? '✓ Kết nối thành công' : healthStatus === 'error' ? '✗ Không thể kết nối' : '○ Đang kiểm tra...'}
            </Badge>
            {healthData && <span className="text-sm text-gray-600">DB: {healthData.database} | IoC: {healthData.alert_count}</span>}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="p-6">
          <div className="flex items-center gap-2 mb-4">
            <PlayCircle className="w-5 h-5 text-green-600" />
            <h3 className="text-lg font-semibold">Collector Scheduler</h3>
          </div>
          <div className="space-y-3 text-sm">
            <p><span className="font-medium">Trạng thái:</span> {collector?.running ? 'Đang chạy' : 'Tạm dừng'} | Interval: {collector?.interval_minutes || 0} phút</p>
            <p><span className="font-medium">Run count:</span> {collector?.run_count || 0} | Feeds: {collector?.collectors?.length || 0}</p>
            <p><span className="font-medium">Last run:</span> {collector?.last_run || 'Chưa có'}</p>
            <Button onClick={triggerCollector}><PlayCircle className="w-4 h-4 mr-2" />Chạy collector thủ công</Button>
          </div>
        </Card>

        <Card className="p-6">
          <div className="flex items-center gap-2 mb-4">
            <Brain className="w-5 h-5 text-purple-600" />
            <h3 className="text-lg font-semibold">Machine Learning</h3>
          </div>
          <div className="space-y-3 text-sm">
            <p><span className="font-medium">Model:</span> {ml?.available ? 'scikit-learn active' : 'Heuristic fallback'}</p>
            <p><span className="font-medium">Accuracy:</span> {ml?.accuracy !== undefined ? `${(ml.accuracy * 100).toFixed(1)}%` : 'N/A'} | Macro F1: {ml?.macro_f1 !== undefined ? `${(ml.macro_f1 * 100).toFixed(1)}%` : 'N/A'}</p>
            <p><span className="font-medium">Labels:</span> {ml?.labels?.join(', ') || 'N/A'}</p>
            <Button onClick={trainModel}><Brain className="w-4 h-4 mr-2" />Train lại model</Button>
          </div>
        </Card>
      </div>

      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <SettingsIcon className="w-5 h-5 text-purple-600" />
          <h3 className="text-lg font-semibold">Công cụ Debug / Demo</h3>
        </div>

        <div className="space-y-3">
          <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
            <div>
              <p className="font-medium">Tạo dữ liệu từ collector/fallback</p>
              <p className="text-sm text-gray-600">Gọi luồng collector, retry/fallback, dedup và scoring</p>
            </div>
            <Button onClick={triggerCollector} variant="outline">Thực hiện</Button>
          </div>

          <div className="flex items-center justify-between p-3 border border-gray-200 rounded-lg">
            <div>
              <p className="font-medium">Telegram test</p>
              <p className="text-sm text-gray-600">Gửi thử thông báo nếu đã cấu hình TELEGRAM_BOT_TOKEN và TELEGRAM_CHAT_ID</p>
            </div>
            <Button onClick={testTelegram} variant="outline"><Send className="w-4 h-4 mr-2" />Gửi thử</Button>
          </div>

          <div className="flex items-center justify-between p-3 border border-red-200 rounded-lg bg-red-50">
            <div>
              <p className="font-medium text-red-900">Reset Database</p>
              <p className="text-sm text-red-700">Xóa toàn bộ dữ liệu và seed lại 916 IoC demo</p>
            </div>
            <Button
              onClick={async () => {
                if (window.confirm('Bạn có chắc muốn reset toàn bộ dữ liệu?')) {
                  try {
                    await api.debug.resetDatabase();
                    toast.success('Đã reset database thành công!');
                    checkHealth();
                    loadStatus();
                  } catch (error) {
                    toast.error('Không thể reset database');
                  }
                }
              }}
              variant="destructive"
            >Reset</Button>
          </div>
        </div>
      </Card>

      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Bell className="w-5 h-5 text-orange-600" />
          <h3 className="text-lg font-semibold">Cài đặt thông báo</h3>
        </div>
        <div className="space-y-3">
          <div className="flex items-center justify-between"><div><p className="font-medium">Thông báo Critical</p><p className="text-sm text-gray-600">Gửi alert khi risk_score vượt ngưỡng</p></div><input type="checkbox" className="w-5 h-5" defaultChecked /></div>
          <div className="flex items-center justify-between"><div><p className="font-medium">Thông báo High</p><p className="text-sm text-gray-600">Theo dõi high severity từ collector</p></div><input type="checkbox" className="w-5 h-5" defaultChecked /></div>
        </div>
      </Card>

      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4"><Shield className="w-5 h-5 text-green-600" /><h3 className="text-lg font-semibold">Cài đặt bảo mật demo</h3></div>
        <div className="space-y-4">
          <div><label className="block text-sm font-medium text-gray-700 mb-2">Thời gian timeout (phút)</label><Input type="number" defaultValue="30" /></div>
          <div><label className="block text-sm font-medium text-gray-700 mb-2">API Key (nếu cần)</label><Input type="password" placeholder="Nhập API key..." /></div>
        </div>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={saving}><Save className="w-4 h-4 mr-2" />{saving ? 'Đang lưu...' : 'Lưu thay đổi'}</Button>
      </div>
    </div>
  );
}
