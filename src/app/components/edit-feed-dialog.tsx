import { useState, useEffect } from 'react';
import { X } from 'lucide-react';
import { Button } from './ui/button';
import { Input } from './ui/input';

interface Feed {
  id: string;
  name: string;
  url: string;
  source?: string;
  enabled?: boolean;
}

interface EditFeedDialogProps {
  isOpen: boolean;
  onClose: () => void;
  onSave?: (feed: Feed) => void;
  feed: Feed | null;
}

export function EditFeedDialog({ isOpen, onClose, onSave, feed }: EditFeedDialogProps) {
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    type: 'RSS',
    enabled: true,
  });

  const [errors, setErrors] = useState<Record<string, string>>({});

  useEffect(() => {
    if (feed) {
      setFormData({
        name: feed.name || '',
        url: feed.url || '',
        type: feed.source || 'RSS',
        enabled: feed.enabled ?? true,
      });
    }
  }, [feed]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const newErrors: Record<string, string> = {};

    if (!formData.name.trim()) {
      newErrors.name = 'Vui lòng nhập tên nguồn';
    }
    if (!formData.url.trim()) {
      newErrors.url = 'Vui lòng nhập URL';
    } else if (!formData.url.startsWith('http://') && !formData.url.startsWith('https://')) {
      newErrors.url = 'URL phải bắt đầu với http:// hoặc https://';
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    if (feed) {
      onSave?.({
        ...feed,
        name: formData.name,
        url: formData.url,
        source: formData.type,
        enabled: formData.enabled
      });
    }
    setErrors({});
    onClose();
  };

  if (!isOpen || !feed) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      <div className="relative bg-white rounded-xl shadow-2xl w-full max-w-md mx-4 p-6 z-10">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-xl font-bold text-gray-900">Chỉnh sửa nguồn</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-gray-600 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Tên nguồn <span className="text-red-500">*</span>
            </label>
            <Input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="Ví dụ: AlienVault OTX"
              className={errors.name ? 'border-red-500' : ''}
            />
            {errors.name && (
              <p className="text-xs text-red-500 mt-1">{errors.name}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              URL <span className="text-red-500">*</span>
            </label>
            <Input
              type="text"
              value={formData.url}
              onChange={(e) => setFormData({ ...formData, url: e.target.value })}
              placeholder="https://example.com/feed"
              className={errors.url ? 'border-red-500' : ''}
            />
            {errors.url && (
              <p className="text-xs text-red-500 mt-1">{errors.url}</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Loại nguồn
            </label>
            <select
              value={formData.type}
              onChange={(e) => setFormData({ ...formData, type: e.target.value })}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="RSS">RSS Feed</option>
              <option value="API">API</option>
              <option value="STIX">STIX/TAXII</option>
              <option value="CSV">CSV</option>
              <option value="JSON">JSON</option>
            </select>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enabled"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
            />
            <label htmlFor="enabled" className="text-sm font-medium text-gray-700">
              Kích hoạt nguồn
            </label>
          </div>

          <div className="flex gap-3 pt-4">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              className="flex-1"
            >
              Hủy
            </Button>
            <Button type="submit" className="flex-1">
              Lưu thay đổi
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
