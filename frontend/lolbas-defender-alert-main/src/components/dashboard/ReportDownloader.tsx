import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import { Download } from "lucide-react";
import { toast } from "sonner";
import { useAlerts } from "@/context/AlertContext";

const ReportDownloader: React.FC = () => {
  const { alerts } = useAlerts();
  const [isLoading, setIsLoading] = useState(false);
  
  const handleDownloadReport = () => {
    if (alerts.length === 0) {
      toast.error("No alerts to generate report");
      return;
    }
    
    setIsLoading(true);
    
    try {
      // Direct link to the new CSV endpoint
      const csvUrl = "http://localhost:5000/download-csv?days=30";
      
      // Create a temporary link and trigger download
      const link = document.createElement('a');
      link.href = csvUrl;
      link.setAttribute('download', ''); // This ensures browser will download the file
      document.body.appendChild(link);
      link.click();
      
      // Clean up
      document.body.removeChild(link);
      
      // Show success message after a short delay to allow download to start
      setTimeout(() => {
        toast.success("CSV Report downloaded successfully");
        setIsLoading(false);
      }, 1000);
    } catch (error) {
      console.error("Error downloading report:", error);
      toast.error("Failed to download report");
      setIsLoading(false);
    }
  };

  return (
    <Button 
      onClick={handleDownloadReport} 
      disabled={isLoading || alerts.length === 0}
      className="ml-auto"
      variant="outline"
    >
      <Download className="mr-2 h-4 w-4" />
      {isLoading ? "Generating..." : "Download CSV Report"}
    </Button>
  );
};

export default ReportDownloader;
