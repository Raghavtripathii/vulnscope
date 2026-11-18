"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { get, post } from "@/lib/api";
import type { Me } from "@/types/auth";

export default function Navbar() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);

  useEffect(() => {
    async function check() {
      try {
        setMe(await get<Me>("/auth/me"));
      } catch {
        setMe(null);
      } finally {
        setChecked(true);
      }
    }
    check();
  }, [pathname]);

  async function handleLogout() {
    try {
      await post("/auth/logout", {});
    } finally {
      setMe(null);
      router.push("/login");
    }
  }

  return (
    <nav className="flex items-center justify-between border-b border-neutral-800 px-6 py-4">
      <Link href="/" className="text-lg font-bold">
        VulnScope
      </Link>
      <div className="flex gap-4 text-sm">
        <Link href="/" className="hover:underline">
          Scan
        </Link>
        {me && (
          <>
            <Link href="/practice" className="hover:underline">
              Practice
            </Link>
            <Link href="/dashboard" className="hover:underline">
              Dashboard
            </Link>
            {me.is_teacher && (
              <Link href="/teacher" className="hover:underline">
                Teacher
              </Link>
            )}
            <span className="text-neutral-400" title="Signed in as">
              {me.email}
            </span>
            <button onClick={handleLogout} className="hover:underline">
              Logout
            </button>
          </>
        )}
        {checked && !me && (
          <>
            <Link href="/login" className="hover:underline">
              Login
            </Link>
            <Link href="/register" className="hover:underline">
              Register
            </Link>
          </>
        )}
      </div>
    </nav>
  );
}