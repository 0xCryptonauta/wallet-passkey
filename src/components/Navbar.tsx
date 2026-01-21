// src/components/Navbar.tsx
import { useState } from "react";
import { useAuth } from "../context/AuthContext";

type TabType = "auth" | "sign" | "verify" | "encrypt";

interface NavbarProps {
  onTabClick: (tab: TabType) => void;
}

export function Navbar({ onTabClick }: NavbarProps) {
  const { isAuthenticated, hasPasskeys, currentWalletAddress } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  return (
    <div className="relative">
      <nav className="flex items-center justify-between px-4 sm:px-8 py-4 border-b border-gray-200 bg-white min-w-[300px]">
        <div className="flex items-center gap-2 text-lg sm:text-xl font-bold tracking-tight">
          <img
            src="/IB_icon.png"
            alt="App icon"
            className="w-8 h-8 sm:w-10 sm:h-10 object-contain"
          />
        </div>

        <div className="flex items-center justify-between flex-1 ml-4 sm:ml-8">
          <ul className="hidden sm:flex gap-6 text-gray-600 font-medium">
            <li
              className="hover:text-blue-600 cursor-pointer transition"
              onClick={() => onTabClick("sign")}
            >
              Sign
            </li>
            <li
              className="hover:text-blue-600 cursor-pointer transition"
              onClick={() => onTabClick("verify")}
            >
              Verify
            </li>
            <li
              className="hover:text-blue-600 cursor-pointer transition"
              onClick={() => onTabClick("encrypt")}
            >
              Encrypt
            </li>
          </ul>

          {/* Mobile menu button */}
          <div className="sm:hidden">
            <button
              className="text-gray-600 hover:text-blue-600 p-2"
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M4 6h16M4 12h16M4 18h16"
                />
              </svg>
            </button>
          </div>

          {/* Show authenticated wallet or Auth tab with status */}
          <div className="flex items-center gap-2">
            {isAuthenticated && currentWalletAddress ? (
              <div
                className="flex items-center gap-2 px-2 sm:px-3 py-1 bg-green-100 text-green-800 rounded-lg text-xs sm:text-sm font-medium cursor-pointer hover:bg-green-200 transition"
                onClick={() => onTabClick("auth")}
              >
                <span className="w-2 h-2 bg-green-500 rounded-full"></span>
                <span>
                  {currentWalletAddress.slice(0, 6)}...
                  {currentWalletAddress.slice(-4)}
                </span>
              </div>
            ) : (
              <div
                className="hover:text-blue-600 cursor-pointer flex items-center gap-2 px-2 sm:px-3 py-1 text-gray-600 font-medium"
                onClick={() => onTabClick("auth")}
              >
                <span>Auth</span>
                <span
                  className={`w-2 h-2 rounded-full ${
                    hasPasskeys ? "bg-yellow-500" : "bg-gray-300"
                  }`}
                ></span>
              </div>
            )}
          </div>
        </div>

        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div className="sm:hidden absolute top-full left-0 right-0 bg-white border-b border-gray-200 shadow-lg z-10">
            <ul className="py-2">
              <li
                className="px-4 py-3 hover:bg-gray-50 cursor-pointer text-gray-600 font-medium"
                onClick={() => {
                  onTabClick("sign");
                  setIsMobileMenuOpen(false);
                }}
              >
                Sign
              </li>
              <li
                className="px-4 py-3 hover:bg-gray-50 cursor-pointer text-gray-600 font-medium"
                onClick={() => {
                  onTabClick("verify");
                  setIsMobileMenuOpen(false);
                }}
              >
                Verify
              </li>
              <li
                className="px-4 py-3 hover:bg-gray-50 cursor-pointer text-gray-600 font-medium"
                onClick={() => {
                  onTabClick("encrypt");
                  setIsMobileMenuOpen(false);
                }}
              >
                Encrypt
              </li>
            </ul>
          </div>
        )}
      </nav>
    </div>
  );
}
