
import React from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useAlerts } from "@/context/AlertContext";

const AlertSeverityChart: React.FC = () => {
  const { alerts } = useAlerts();
  
  // Count alerts by severity level
  const criticalCount = alerts.filter(a => a.lolbin.riskLevel === "critical").length;
  const highCount = alerts.filter(a => a.lolbin.riskLevel === "high").length;
  const mediumCount = alerts.filter(a => a.lolbin.riskLevel === "medium").length;
  const lowCount = alerts.filter(a => a.lolbin.riskLevel === "low").length;
  
  // Generate a simple pie chart as base64 PNG
  // This would normally be generated on the server, but for demo purposes we're using a placeholder
  const chartImageBase64 = "data:image/png;base64,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";

  return (
    <Card>
      <CardHeader>
        <CardTitle>Alert Severity Breakdown</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center">
        {alerts.length > 0 ? (
          <>
            <img 
              src={chartImageBase64} 
              alt="Severity breakdown chart" 
              className="w-64 h-64 mb-4"
            />
            <div className="grid grid-cols-2 gap-4 w-full">
              <div className="flex items-center">
                <div className="h-3 w-3 rounded-full bg-critical mr-2"></div>
                <span className="text-sm">Critical: {criticalCount}</span>
              </div>
              <div className="flex items-center">
                <div className="h-3 w-3 rounded-full bg-warning mr-2"></div>
                <span className="text-sm">High: {highCount}</span>
              </div>
              <div className="flex items-center">
                <div className="h-3 w-3 rounded-full bg-info mr-2"></div>
                <span className="text-sm">Medium: {mediumCount}</span>
              </div>
              <div className="flex items-center">
                <div className="h-3 w-3 rounded-full bg-success mr-2"></div>
                <span className="text-sm">Low: {lowCount}</span>
              </div>
            </div>
          </>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            No alerts to display
          </div>
        )}
      </CardContent>
    </Card>
  );
};

export default AlertSeverityChart;
