import { createBrowserRouter } from "react-router";
import { DashboardLayout } from "./components/dashboard-layout";
import { OverviewPage } from "./pages/overview";
import { ThreatMapPage } from "./pages/threat-map-page";
import { AnalyticsPage } from "./pages/analytics";
import { ThreatsPage } from "./pages/threats";
import { ActivityPage } from "./pages/activity";
import { FeedsPage } from "./pages/feeds";
import { SettingsPage } from "./pages/settings";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <DashboardLayout />,
    children: [
      { index: true, Component: OverviewPage },
      { path: "map", Component: ThreatMapPage },
      { path: "analytics", Component: AnalyticsPage },
      { path: "threats", Component: ThreatsPage },
      { path: "activity", Component: ActivityPage },
      { path: "feeds", Component: FeedsPage },
      { path: "settings", Component: SettingsPage },
    ],
  },
]);
