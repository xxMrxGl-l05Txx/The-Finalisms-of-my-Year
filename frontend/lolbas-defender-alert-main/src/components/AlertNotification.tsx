import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { useAlerts } from "@/context/AlertContext";
import { ShieldAlert } from "lucide-react";

const AlertNotification: React.FC = () => {
  const { alerts } = useAlerts();
  const navigate = useNavigate();
  const [showAlert, setShowAlert] = useState(false);
  const [currentAlert, setCurrentAlert] = useState<string | null>(null);
  const [lastShownTime, setLastShownTime] = useState<number | null>(null);
  const [fadeOut, setFadeOut] = useState(false);
  
  useEffect(() => {
    // Look for new alerts
    const newAlerts = alerts.filter(alert => alert.status === "new");
    const now = Date.now();
    const minInterval = 10000; // 10 seconds minimum between alerts
    
    if (newAlerts.length > 0 && !showAlert && (!lastShownTime || now - lastShownTime > minInterval)) {
      const latestAlert = newAlerts[0];
      setCurrentAlert(latestAlert.id);
      setShowAlert(true);
      setLastShownTime(now);
      setFadeOut(false);
      
      // Start fade-out animation after 7 seconds
      const fadeTimer = setTimeout(() => {
        setFadeOut(true);
      }, 7000);
      
      // Hide after 8 seconds
      const hideTimer = setTimeout(() => {
        setShowAlert(false);
      }, 8000);
      
      return () => {
        clearTimeout(fadeTimer);
        clearTimeout(hideTimer);
      };
    }
  }, [alerts, showAlert, lastShownTime]);
  
  if (!showAlert || !currentAlert) {
    return null;
  }
  
  const alert = alerts.find(a => a.id === currentAlert);
  if (!alert) {
    return null;
  }
  
  return (
    <div className={`fixed bottom-4 right-4 max-w-sm z-50 alert-notification transition-opacity duration-1000 ${fadeOut ? 'opacity-0' : 'opacity-100'}`}>
      <Card className="border-critical/30 bg-critical/10 shadow-lg">
        <CardContent className="p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-full bg-critical/20">
              <ShieldAlert className="h-6 w-6 text-critical" />
            </div>
            <div>
              <h4 className="font-medium">LOLBin Alert</h4>
              <p className="text-sm text-muted-foreground">{alert.lolbin.name} detected</p>
            </div>
          </div>
          <p className="mt-2 text-sm">{alert.details}</p>
        </CardContent>
        <CardFooter className="flex justify-end gap-2 p-3 pt-0">
          <Button 
            variant="ghost" 
            size="sm"
            onClick={() => {
              setFadeOut(true);
              setTimeout(() => setShowAlert(false), 1000);
            }}
          >
            Dismiss
          </Button>
          <Button 
            size="sm"
            onClick={() => {
              navigate(`/alert/${alert.id}`);
              setShowAlert(false);
            }}
          >
            View Details
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
};

export default AlertNotification;
