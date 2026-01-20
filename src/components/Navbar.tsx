// src/components/Navbar.tsx
import { Account } from "./Account";

export function Navbar() {
  return (
    <nav className="flex items-center justify-between px-8 py-4 border-b border-gray-200 bg-white">
      <div className="flex items-center gap-2 text-xl font-bold tracking-tight">
        <img
          src="/IB_icon.png"
          alt="App icon"
          className="w-6 h-6 object-contain"
        />
      </div>

      <div className="flex items-center gap-8">
        <Account />
      </div>
    </nav>
  );
}
