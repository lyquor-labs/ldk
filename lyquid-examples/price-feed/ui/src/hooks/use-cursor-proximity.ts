import { useState, useEffect } from 'react';
import type { RefObject } from 'react';

export const useCursorProximity = (
    ref: RefObject<HTMLElement | null>,
    proximity: number = 100 // Distance in px to start triggering
) => {
    const [isNear, setIsNear] = useState(false);
    const [cursorPos, setCursorPos] = useState({ x: -1000, y: -1000 }); // Relative to element

    useEffect(() => {
        const handleMouseMove = (e: MouseEvent) => {
            if (!ref.current) return;

            const rect = ref.current.getBoundingClientRect();
            // Get cursor position relative to the element's top-left corner
            const relativeX = e.clientX - rect.left;
            const relativeY = e.clientY - rect.top;

            // Check distance to the rectangle's bounding box
            const distanceX = Math.max(rect.left - e.clientX, 0, e.clientX - rect.right);
            const distanceY = Math.max(rect.top - e.clientY, 0, e.clientY - rect.bottom);
            const distance = Math.sqrt(distanceX ** 2 + distanceY ** 2);

            if (distance < proximity) {
                setIsNear(true);
                setCursorPos({ x: relativeX, y: relativeY });
            } else {
                setIsNear(false);
                // Keep updating position even if far?
                // No, maybe reset or just let it stay at last known pos,
                // but usually we want to hide it when far.
                // We'll update pos anyway so the exit animation is smooth if we want.
                setCursorPos({ x: relativeX, y: relativeY });
            }
        };

        window.addEventListener('mousemove', handleMouseMove);
        return () => window.removeEventListener('mousemove', handleMouseMove);
    }, [ref, proximity]);

    return { isNear, cursorPos };
};
