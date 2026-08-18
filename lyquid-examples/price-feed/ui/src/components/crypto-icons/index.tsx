import { JazzAvatar } from "@/components/jazzicon/jazzavatar";
import { cn, Skeleton } from "lyquor-shadcn";
import { useRequest } from "ahooks";
import { cryptoIconUrls } from "virtual:price-feed-crypto-icons";

// The icons are bundled static assets, but they are inlined so theme styles can
// address their SVG nodes. Cache the fetch promise at module scope: list rows
// may remount during live updates, and an icon must not refetch for each row.
const iconRequests = new Map<string, Promise<string | undefined>>();

const loadIcon = (token: string) => {
    const url = cryptoIconUrls[token.toUpperCase()];
    if (!url) return Promise.resolve(undefined);
    const cached = iconRequests.get(url);
    if (cached) return cached;

    const request = fetch(url, { cache: "force-cache" })
        .then((response) => response.ok && response.headers.get("content-type")?.includes("image/svg+xml") ? response.text() : undefined)
        .catch((error) => {
            iconRequests.delete(url);
            throw error;
        });
    iconRequests.set(url, request);
    return request;
};

export const CryptoIcons = ({
    token,
    size = 16,
    className = "",
}: {
    token: string;
    size?: number;
    className?: string;
}) => {
    const { data, loading, error } = useRequest(() => loadIcon(token), {
        ready: Boolean(token),
        refreshDeps: [token],
    });

    return <div className={cn(" [&_svg]:size-full! ", className)} style={{ width: size + 'px', height: size + 'px' }}>
        {
            loading ? (
                <Skeleton className={cn('size-full', "rounded-full", className)} />
            ) : (error || !data) ? (
                <JazzAvatar
                    address={token}
                    size={size}
                    className={cn("rounded-full", className)}
                />
            ) : data?.startsWith("<svg") ? (
                <div
                    dangerouslySetInnerHTML={{ __html: data }}
                    className={cn('size-full flex items-center justify-center', "rounded-full", className)}
                />
            ) : (
                <img
                    src={data}
                    alt={token}
                    className={cn('size-full', "rounded-full", className)}
                />
            )
        }
    </div>;
};
