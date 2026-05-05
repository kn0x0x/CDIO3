import { useState } from 'react';
import { Card } from '../components/ui/card';
import { Button } from '../components/ui/button';
import { Input } from '../components/ui/input';
import { Badge } from '../components/ui/badge';
import { Plus, RefreshCw, Trash2, Edit, Power } from 'lucide-react';
import { useAPI } from '../hooks/use-api';
import { api } from '../services/api';
import { AddFeedDialog } from '../components/add-feed-dialog';
import { EditFeedDialog } from '../components/edit-feed-dialog';
import { DeleteConfirmDialog } from '../components/delete-confirm-dialog';
import { toast } from 'sonner';

export function FeedsPage() {
  const { data: feeds, loading, error, refetch } = useAPI(() => api.feeds.list(), []);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [selectedFeed, setSelectedFeed] = useState<any>(null);
  const [feedStatuses, setFeedStatuses] = useState<Record<string, boolean>>({});

  const isAdmin = true;

  const handleAddFeed = async (feedData: any) => {
    try {
      await api.feeds.create(feedData);
      toast.success(`Đã thêm nguồn "${feedData.name}" thành công!`);
      refetch();
    } catch (error: any) {
      toast.error(error.message || 'Không thể thêm nguồn');
    }
  };

  const handleEditFeed = async (feedData: any) => {
    try {
      await api.feeds.update(feedData.id, feedData);
      toast.success(`Đã cập nhật nguồn "${feedData.name}" thành công!`);
      refetch();
    } catch (error: any) {
      toast.error(error.message || 'Không thể cập nhật nguồn');
    }
  };

  const handleDeleteFeed = async () => {
    if (selectedFeed) {
      try {
        await api.feeds.delete(selectedFeed.id);
        toast.success(`Đã xóa nguồn "${selectedFeed.name}" thành công!`);
        refetch();
      } catch (error: any) {
        toast.error(error.message || 'Không thể xóa nguồn');
      }
    }
  };

  const openEditModal = (feed: any) => {
    setSelectedFeed(feed);
    setShowEditModal(true);
  };

  const openDeleteModal = (feed: any) => {
    setSelectedFeed(feed);
    setShowDeleteModal(true);
  };

  const toggleFeedStatus = async (feed: any) => {
    const currentStatus = feedStatuses[feed.id] ?? feed.enabled;
    const newStatus = !currentStatus;
    setFeedStatuses(prev => ({ ...prev, [feed.id]: newStatus }));

    try {
      await api.feeds.update(feed.id, { enabled: newStatus });
      toast.success(
        newStatus
          ? `Đã kích hoạt nguồn "${feed.name}"`
          : `Đã tạm dừng nguồn "${feed.name}"`
      );
      refetch();
    } catch (error: any) {
      setFeedStatuses(prev => ({ ...prev, [feed.id]: currentStatus }));
      toast.error(error.message || 'Không thể đổi trạng thái nguồn');
    }
  };

  const getFeedStatus = (feed: any) => {
    return feedStatuses[feed.id] ?? feed.enabled;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto"></div>
          <p className="mt-4 text-gray-600">Đang tải nguồn cấp dữ liệu...</p>
        </div>
      </div>
    );
  }

  const feedList = feeds || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Nguồn cấp dữ liệu</h2>
          <p className="text-gray-600 mt-1">Quản lý các nguồn threat intelligence</p>
        </div>
        <div className="flex gap-2">
          <Button onClick={refetch} variant="outline">
            <RefreshCw className="w-4 h-4 mr-2" />
            Làm mới
          </Button>
          {isAdmin && (
            <Button onClick={() => setShowAddModal(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Thêm nguồn
            </Button>
          )}
        </div>
      </div>

      {error && (
        <Card className="p-4 bg-yellow-50 border-yellow-200">
          <p className="text-sm text-yellow-800">⚠️ Không thể kết nối API: {error.message}</p>
        </Card>
      )}

      {/* Feeds Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {feedList.map((feed) => (
          <Card key={feed.id} className="p-6">
            <div className="flex items-start justify-between mb-4">
              <div className="flex-1">
                <h3 className="font-semibold text-lg mb-1">{feed.name}</h3>
                <p className="text-sm text-gray-600 mb-2">{feed.source}</p>
                <Badge variant={getFeedStatus(feed) ? 'default' : 'secondary'}>
                  {getFeedStatus(feed) ? 'Đang hoạt động' : 'Tạm dừng'}
                </Badge>
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => toggleFeedStatus(feed)}
                className={`transition-colors ${
                  getFeedStatus(feed)
                    ? 'text-green-600 hover:text-green-700 hover:bg-green-50'
                    : 'text-red-500 hover:text-red-600 hover:bg-red-50'
                }`}
                title={getFeedStatus(feed) ? 'Tạm dừng nguồn' : 'Kích hoạt nguồn'}
              >
                <Power className="w-4 h-4" />
              </Button>
            </div>

            <div className="space-y-2 mb-4">
              <div className="text-xs text-gray-600">
                <span className="font-medium">URL:</span>
                <p className="truncate mt-1">{feed.url}</p>
              </div>
              {feed.last_updated && (
                <div className="text-xs text-gray-600">
                  <span className="font-medium">Cập nhật lần cuối:</span>
                  <p className="mt-1">{new Date(feed.last_updated).toLocaleString('vi-VN')}</p>
                </div>
              )}
            </div>

            {isAdmin && (
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => openEditModal(feed)}
                >
                  <Edit className="w-3 h-3 mr-1" />
                  Sửa
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-red-600 hover:text-red-700 hover:bg-red-50"
                  onClick={() => openDeleteModal(feed)}
                >
                  <Trash2 className="w-3 h-3" />
                </Button>
              </div>
            )}
          </Card>
        ))}
      </div>

      {feedList.length === 0 && !loading && (
        <Card className="p-12">
          <div className="text-center">
            <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <Plus className="w-8 h-8 text-gray-400" />
            </div>
            <h3 className="text-lg font-semibold mb-2">Chưa có nguồn cấp dữ liệu</h3>
            <p className="text-gray-600 mb-4">Thêm nguồn threat intelligence để bắt đầu</p>
            <Button onClick={() => setShowAddModal(true)}>
              <Plus className="w-4 h-4 mr-2" />
              Thêm nguồn đầu tiên
            </Button>
          </div>
        </Card>
      )}

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-sm text-gray-600">Tổng nguồn</p>
          <p className="text-2xl font-bold mt-1">{feedList.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Đang hoạt động</p>
          <p className="text-2xl font-bold mt-1 text-green-600">
            {feedList.filter(f => getFeedStatus(f)).length}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Tạm dừng</p>
          <p className="text-2xl font-bold mt-1 text-red-600">
            {feedList.filter(f => !getFeedStatus(f)).length}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-gray-600">Cập nhật hôm nay</p>
          <p className="text-2xl font-bold mt-1 text-blue-600">
            {feedList.filter(f => {
              if (!f.last_updated) return false;
              const today = new Date().toDateString();
              return new Date(f.last_updated).toDateString() === today;
            }).length}
          </p>
        </Card>
      </div>

      <AddFeedDialog
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        onAdd={handleAddFeed}
      />

      <EditFeedDialog
        isOpen={showEditModal}
        onClose={() => setShowEditModal(false)}
        onSave={handleEditFeed}
        feed={selectedFeed}
      />

      <DeleteConfirmDialog
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        onConfirm={handleDeleteFeed}
        title="Xóa nguồn cấp dữ liệu?"
        message={`Bạn có chắc chắn muốn xóa nguồn "${selectedFeed?.name}"? Hành động này không thể hoàn tác.`}
      />
    </div>
  );
}
