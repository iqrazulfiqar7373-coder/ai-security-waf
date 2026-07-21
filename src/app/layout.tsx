import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'AI Security Guard & WAF',
  description: 'Enterprise-grade AI-powered Web Application Firewall',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  )
}