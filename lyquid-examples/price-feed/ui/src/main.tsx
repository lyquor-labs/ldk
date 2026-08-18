import { createRoot } from 'react-dom/client'
import { RouterProvider } from "react-router";
import { router } from '@/route';
import './index.css'
import { useThemeStore } from "@/stores/theme-store";

useThemeStore.getState().restore();

createRoot(document.getElementById('root')!).render(<RouterProvider router={router} />)
