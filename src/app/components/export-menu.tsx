import { useState, useRef, useEffect } from 'react';
import { Download, FileText, FileSpreadsheet, FileJson, File } from 'lucide-react';
import { Button } from './ui/button';

interface ExportMenuProps {
  data: any[];
  filename?: string;
}

export function ExportMenu({ data, filename = 'export' }: ExportMenuProps) {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const exportToCSV = () => {
    if (data.length === 0) return;

    const headers = Object.keys(data[0]);
    const csvContent = [
      headers.join(','),
      ...data.map(row =>
        headers.map(header => {
          const value = row[header];
          return typeof value === 'string' && value.includes(',')
            ? `"${value}"`
            : value;
        }).join(',')
      )
    ].join('\n');

    downloadFile(csvContent, `${filename}.csv`, 'text/csv');
    setIsOpen(false);
  };

  const exportToJSON = () => {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, `${filename}.json`, 'application/json');
    setIsOpen(false);
  };

  const exportToExcel = () => {
    // Simple Excel-compatible format (TSV)
    if (data.length === 0) return;

    const headers = Object.keys(data[0]);
    const tsvContent = [
      headers.join('\t'),
      ...data.map(row =>
        headers.map(header => row[header]).join('\t')
      )
    ].join('\n');

    downloadFile(tsvContent, `${filename}.xls`, 'application/vnd.ms-excel');
    setIsOpen(false);
  };

  const exportToPDF = () => {
    // Create simple HTML for PDF conversion
    const html = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="utf-8">
          <title>${filename}</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f3f4f6; font-weight: bold; }
            h1 { color: #333; }
          </style>
        </head>
        <body>
          <h1>Báo cáo: ${filename}</h1>
          <p>Ngày xuất: ${new Date().toLocaleString('vi-VN')}</p>
          <table>
            <thead>
              <tr>
                ${Object.keys(data[0] || {}).map(key => `<th>${key}</th>`).join('')}
              </tr>
            </thead>
            <tbody>
              ${data.map(row => `
                <tr>
                  ${Object.values(row).map(val => `<td>${val}</td>`).join('')}
                </tr>
              `).join('')}
            </tbody>
          </table>
        </body>
      </html>
    `;

    downloadFile(html, `${filename}.html`, 'text/html');
    setIsOpen(false);
  };

  const downloadFile = (content: string, filename: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="relative" ref={menuRef}>
      <Button
        variant="outline"
        onClick={() => setIsOpen(!isOpen)}
      >
        <Download className="w-4 h-4 mr-2" />
        Xuất
      </Button>

      {isOpen && (
        <div className="absolute right-0 mt-2 w-48 bg-white rounded-lg shadow-lg border border-gray-200 py-1 z-50">
          <button
            onClick={exportToCSV}
            className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50 flex items-center gap-2 transition"
          >
            <FileSpreadsheet className="w-4 h-4 text-green-600" />
            <span>Xuất CSV</span>
          </button>
          <button
            onClick={exportToExcel}
            className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50 flex items-center gap-2 transition"
          >
            <FileSpreadsheet className="w-4 h-4 text-green-700" />
            <span>Xuất Excel</span>
          </button>
          <button
            onClick={exportToJSON}
            className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50 flex items-center gap-2 transition"
          >
            <FileJson className="w-4 h-4 text-blue-600" />
            <span>Xuất JSON</span>
          </button>
          <button
            onClick={exportToPDF}
            className="w-full px-4 py-2 text-left text-sm hover:bg-gray-50 flex items-center gap-2 transition"
          >
            <FileText className="w-4 h-4 text-red-600" />
            <span>Xuất PDF/HTML</span>
          </button>
        </div>
      )}
    </div>
  );
}
