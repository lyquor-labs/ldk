export const Progress = ({ percentage = 100, length = 10 }: { percentage?: number, length?: number }) => {
    const activeCount = Math.round((percentage / 100) * length);

    return (
        <div className="flex items-center gap-1">
            {Array.from({ length }).map((_, idx) => {
                const isActive = idx < activeCount;



                const positionRatio = idx / length;

                let activeColor = "bg-red-500";
                if (positionRatio >= 0.66) {
                    activeColor = "bg-green-500";
                } else if (positionRatio >= 0.33) {
                    activeColor = "bg-yellow-500";
                }

                return (
                    <div
                        key={idx}
                        className={`size-1.5 transition-colors duration-200 ${
                            isActive ? activeColor : "bg-foreground/20"
                        }`}
                    />
                );
            })}
        </div>
    )
}