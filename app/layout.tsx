import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "JWT Glass — client-side token inspector",
  description:
    "Decode and inspect JWT header and payload locally. Nothing leaves the browser. Portfolio demo by Saeed Rumaneh.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
