import { useRef } from 'react';
import { cn } from "@/lib/utils";
import { useCursorProximity } from "@/hooks/use-cursor-proximity";

interface SketchRevealProps {
    className?: string;
    origin: string; // The sketch image (default visible)
    reveal: string; // The real logo (revealed on hover)
    size?: number;  // Size of the reveal circle in pixels
    proximity?: number; // How close cursor needs to be to start revealing (in pixels)
}

export const SketchReveal = ({
    className,
    origin,
    reveal,
    size = 40,
    proximity = 100
}: SketchRevealProps) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const { isNear, cursorPos } = useCursorProximity(containerRef, proximity);

    return (
        <div
            ref={containerRef}
            className={cn("relative overflow-hidden cursor-crosshair", className)}
        >
            {/* Base Layer: Sketch Image (Always visible as background) */}
            <img
                src={origin}
                alt="Sketch"
                className="orgin-img w-full h-full object-contain pointer-events-none select-none"
            />

            {/* Reveal Layer: Real Logo (Top layer, masked to show only under cursor) */}
            <div
                className="absolute inset-0 pointer-events-none select-none"
                style={{
                    opacity: isNear ? 1 : 0,
                    transition: 'opacity 0.2s ease-out',
                    // Using mask-image to create a "hole" or "spotlight" effect on the TOP layer
                    maskImage: `radial-gradient(circle ${size}px at ${cursorPos.x}px ${cursorPos.y}px, black 100%, transparent 100%)`,
                    WebkitMaskImage: `radial-gradient(circle ${size}px at ${cursorPos.x}px ${cursorPos.y}px, black 100%, transparent 100%)`,
                }}
            >
                 <img
                    src={reveal}
                    alt="Reveal"
                    className="reveal-img w-full h-full object-contain pointer-events-none rounded-full"
                />
            </div>
        </div>
    );
};
