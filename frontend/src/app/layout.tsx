import type { Metadata } from "next";
import "./globals.css";
import { TooltipProvider } from "@/components/ui/tooltip";

export const metadata: Metadata = {
  title: "ECDAT | Enterprise Cryptographic Discovery & Analysis Tool",
  description:
    "Evidence-based source, TLS, and binary cryptographic discovery with persistent scan history. NTRO / SIH26164 prototype.",
  keywords: ["cryptography", "security", "PQC", "CBOM", "quantum risk", "migration"],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem("ecdat-theme-v2");document.documentElement.classList.toggle("dark",t==null||t==="dark")}catch(e){document.documentElement.classList.add("dark")}})();`,
          }}
        />
      </head>
      <body className="antialiased bg-background text-foreground">
        <TooltipProvider>{children}</TooltipProvider>
      </body>
    </html>
  );
}
