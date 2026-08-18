import NavLayout from "@/layouts/nav-layout";
import { createBrowserRouter, Navigate } from "react-router";
import { Home } from "@/page";
import { FeedPage } from "@/page/feed/page";
import { ExplorerPage } from "@/page/explorer/page";
import OperatorLayout from "@/layouts/operator-layout";
import { SetupPage } from "@/page/setup/page";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <Home />,
  },
  {
    path: "/feeds",
    element: <Navigate to="/feeds/BTC" />,
  },
  {
    path: "/feeds/:asset",
    element: <NavLayout />,
    children: [
      {
        index: true,
        element: <FeedPage />,
      },
    ]
  },
  {
    path: "/explorer",
    element: <NavLayout />,
    children: [
      {
        index: true,
        element: <ExplorerPage />,
      },
      {
        path: "tx/:txHash",
        element: <ExplorerPage />,
      },
      {
        path: "block/:blockNumber",
        element: <ExplorerPage />,
      },
    ]
  },
  {
    path: "/setup",
    element: <OperatorLayout />,
    children: [
      {
        index: true,
        element: <SetupPage />,
      },
    ],
  },
]);
