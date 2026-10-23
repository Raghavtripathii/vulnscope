import Link from "next/link";

export default function Navbar() {
  return (
    <nav className="flex items-center justify-between border-b border-neutral-800 px-6 py-4">
      <Link href="/" className="text-lg font-bold">
        VulnScope
      </Link>
      <div className="flex gap-4 text-sm">
        <Link href="/" className="hover:underline">
          Scan
        </Link>
        <Link href="/login" className="hover:underline">
          Login
        </Link>
        <Link href="/register" className="hover:underline">
          Register
        </Link>
      </div>
    </nav>
  );
}