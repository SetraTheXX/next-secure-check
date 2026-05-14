import "./globals.css";

export const metadata = {
  title: "next-secure-check Web Demo",
  description: "Public GitHub repo security scan demo"
};

export default function RootLayout({
  children
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div className="page">
          {children}
        </div>
      </body>
    </html>
  );
}
