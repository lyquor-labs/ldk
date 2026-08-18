import { JazzAvatar } from "@/components/jazzicon/jazzavatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "lyquor-shadcn/ui/dropdown-menu";
import {
  CircleX,
} from "lucide-react";
import { useAccount, useConnect, useDisconnect } from "wagmi";
import Copy from "@/components/copy";
import { Link } from "react-router";
import { Button } from "lyquor-shadcn";
import { Theme } from "@/components/theme";

const navs = [
  {
    label: "Home",
    href: "/",
  },
  {
    label: "Feeds",
    href: "/feeds",
  },
  {
    label: "Explorer",
    href: "/explorer",
  },
];

export const HeadNav = () => {
  const { address, isConnected } = useAccount();
  const { connect, connectors } = useConnect();
  const { disconnect } = useDisconnect();
  return (
    <div className="h-16 w-full border-b border-border">
      <div className="max-w-[1400px] mx-auto px-6 h-full w-full relative">
        <div className="absolute top-1/2 -translate-y-1/2 left-6 flex items-center gap-2">
          <div className="p-1.5 bg-black aspect-square ">
            <img src="/logo_light.svg" alt="logo" className="size-6" />
          </div>
          <span>Price Feed</span>
        </div>

        <div className="h-full flex items-center gap-12 justify-center">
          {
            navs.map((nav, idx) => (
              <>
              <Link to={nav.href} key={nav.href}>
                <span className="text-sm">{nav.label}</span>
              </Link>
              {idx < navs.length - 1 && <div className="size-1.5 bg-foreground"/>}
              </>
            ))
          }
        </div>

        <div className="absolute top-1/2 -translate-y-1/2 right-6 flex items-center gap-2">
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <div className="cursor-pointer overflow-hidden">
                {isConnected ? (
                  <div className="flex items-center gap-1 ">
                    <JazzAvatar size={38} address={address} />
                  </div>
                ) : (
                  <Button>Connect Wallet</Button>
                )}
              </div>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              side="bottom"
              className="w-fit text-sm"
              align="end"
            >
              {isConnected ? (
                <>
                  <DropdownMenuItem className="flex items-center gap-2 justify-between">
                    <Copy
                      content={address}
                      className="[&_svg]:size-4! w-full flex items-center justify-between"
                      children={
                        <span>{`${address?.slice(0,6)}...${address?.slice(-4)}`}</span>
                      }
                    />
                  </DropdownMenuItem>
                  <DropdownMenuItem
                    className="flex items-center gap-2 justify-between"
                    onClick={() => disconnect()}
                  >
                    <span >Disconnect</span>
                    <CircleX className="size-4" />
                  </DropdownMenuItem>
                </>
              ) : (
                <>
                  {connectors?.map((connector) => (
                    <DropdownMenuItem
                      key={connector.id}
                      onClick={() => connect({ connector })}
                      className="text-sm"
                    >
                      {connector.name}
                    </DropdownMenuItem>
                  ))}
                </>
              )}
            </DropdownMenuContent>
          </DropdownMenu>
          <div className="text-foreground hover:text-background  cursor-pointer border border-foreground hover:bg-foreground">
            <Theme className="p-2" />
          </div>
        </div>
      </div>
    </div>
  );
};
