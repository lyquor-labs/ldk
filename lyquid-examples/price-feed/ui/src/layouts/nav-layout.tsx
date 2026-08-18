import { HeadNav } from "@/components/head-nav";
import { WalletProvider } from "@/layouts/provider/wallet-provider";
import { useMarketStore } from "@/stores/market-store";
import { Toaster } from "lyquor-shadcn/ui/sonner"
import { useEventListener } from "ahooks";
import { useEffect } from "react";
import { Outlet, useNavigate, useParams } from "react-router";


export default function NavLayout() {
  const { asset } = useParams();
  const navigate = useNavigate();
  const { setSelectedAsset, _setSelectedAsset } = useMarketStore();

  useEffect(() => {
    if (asset) {
      setSelectedAsset(asset);
    }
  }, [asset, setSelectedAsset]);


  useEventListener('asset-selected', (event: CustomEvent) => {
    navigate(`/feeds/${event.detail}`);

    _setSelectedAsset(event.detail);
  })

  return (
    <>
      <Toaster />


      <WalletProvider>
        <HeadNav />
        <div><Outlet /></div>
      </WalletProvider>
    </>
  );
}
