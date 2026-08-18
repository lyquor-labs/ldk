import { HeadNav } from "@/components/head-nav"
import { WalletProvider } from "@/layouts/provider/wallet-provider"
import { Toaster } from "lyquor-shadcn/ui/sonner"
import { Outlet } from "react-router"

/** The unlisted operator route reuses the public shell without adding a nav item. */
export default function OperatorLayout() {
  return (
    <>
      <Toaster />
      <WalletProvider>
        <HeadNav />
        <Outlet />
      </WalletProvider>
    </>
  )
}
