import { useEffect, useRef } from 'react';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

export interface ThreatLocation {
  id: string;
  lat: number;
  lng: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  description: string;
  count: number;
}

interface ThreatMapProps {
  threats: ThreatLocation[];
}

const severityColors = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#f59e0b',
  low: '#eab308'
};

export function ThreatMap({ threats }: ThreatMapProps) {
  const mapRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);

  useEffect(() => {
    if (!mapRef.current || mapInstanceRef.current) return;

    // Initialize map
    const map = L.map(mapRef.current).setView([20, 0], 2);
    mapInstanceRef.current = map;

    // Add tile layer
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(map);

    return () => {
      if (mapInstanceRef.current) {
        mapInstanceRef.current.remove();
        mapInstanceRef.current = null;
      }
    };
  }, []);

  useEffect(() => {
    if (!mapInstanceRef.current) return;

    const map = mapInstanceRef.current;

    // Clear existing layers (except tile layer)
    map.eachLayer((layer) => {
      if (layer instanceof L.Circle) {
        map.removeLayer(layer);
      }
    });

    // Add threat circles
    threats.forEach((threat) => {
      const circle = L.circle([threat.lat, threat.lng], {
        color: severityColors[threat.severity],
        fillColor: severityColors[threat.severity],
        fillOpacity: 0.3,
        radius: threat.count * 50000
      }).addTo(map);

      const severityClass = 
        threat.severity === 'critical' ? 'bg-red-100 text-red-800' :
        threat.severity === 'high' ? 'bg-orange-100 text-orange-800' :
        threat.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
        'bg-green-100 text-green-800';

      circle.bindPopup(`
        <div class="p-2">
          <h3 class="font-semibold text-base">${threat.type}</h3>
          <p class="text-sm text-gray-600 mt-1">${threat.description}</p>
          <div class="mt-2">
            <span class="text-xs px-2 py-1 rounded ${severityClass}">
              ${threat.severity.toUpperCase()}
            </span>
            <span class="ml-2 text-sm">${threat.count} threats</span>
          </div>
        </div>
      `);
    });
  }, [threats]);

  return <div ref={mapRef} style={{ height: '100%', width: '100%', borderRadius: '0.5rem' }} />;
}