// {theme === "light" ? <Sun className="size-4  text-background" /> : <Moon className="size-4  text-background" />}

import { useThemeStore } from "@/stores/theme-store";
import { Sun, Moon } from "lucide-react";
import { cn } from "lyquor-shadcn";

export const Theme = ({className}: {className?: string}) => {
    const { theme, toggleTheme } = useThemeStore();
    return (
        <div onClick={() => toggleTheme(theme === "light" ? "dark" : "light")} className={cn("cursor-pointer overflow-hidden", className)}  >
            {theme === "light" ? <Sun className="size-5 " /> : <Moon className="size-5 " />}
        </div>
    )
}