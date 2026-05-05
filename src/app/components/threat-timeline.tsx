import { Card } from './ui/card';
import { Shield, AlertTriangle, Bug, Lock } from 'lucide-react';

export interface ThreatEvent {
  id: string;
  time: string;
  type: 'malware' | 'phishing' | 'ddos' | 'breach';
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

interface ThreatTimelineProps {
  events: ThreatEvent[];
}

const typeIcons = {
  malware: Bug,
  phishing: AlertTriangle,
  ddos: Shield,
  breach: Lock,
};

const severityColors = {
  critical: 'bg-red-100 text-red-800 border-red-300',
  high: 'bg-orange-100 text-orange-800 border-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  low: 'bg-green-100 text-green-800 border-green-300',
};

export function ThreatTimeline({ events }: ThreatTimelineProps) {
  return (
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Recent Threats</h3>
      <div className="space-y-4 max-h-96 overflow-y-auto">
        {events.map((event) => {
          const Icon = typeIcons[event.type];
          return (
            <div key={event.id} className="flex items-start gap-3 pb-4 border-b last:border-0">
              <div className={`p-2 rounded-lg ${severityColors[event.severity]}`}>
                <Icon className="w-4 h-4" />
              </div>
              <div className="flex-1">
                <div className="flex items-start justify-between">
                  <h4 className="font-medium text-sm">{event.title}</h4>
                  <span className="text-xs text-gray-500">{event.time}</span>
                </div>
                <p className="text-sm text-gray-600 mt-1">{event.description}</p>
                <div className="flex items-center gap-2 mt-2">
                  <span className={`text-xs px-2 py-1 rounded ${severityColors[event.severity]}`}>
                    {event.severity}
                  </span>
                  <span className="text-xs text-gray-500">{event.type}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </Card>
  );
}
