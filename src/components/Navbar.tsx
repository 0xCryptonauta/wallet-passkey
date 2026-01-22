// src/components/Navbar.tsx
import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useEnsName } from "wagmi";
import cache from "../lib/accountCache";

type TabType = "sign" | "verify" | "encrypt" | "decrypt";

interface NavbarProps {
  onTabClick: (tab: TabType) => void;
  onAuthClick: () => void;
}

export function Navbar({ onTabClick, onAuthClick }: NavbarProps) {
  const { isAuthenticated, currentWalletAddress } = useAuth();
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  // ENS lookup for navbar display
  const initialEns = currentWalletAddress
    ? cache.readEns(currentWalletAddress)
    : null;
  const { data: ensNameData } = useEnsName({
    address: currentWalletAddress as `0x${string}` | undefined,
    chainId: 1,
    query: { enabled: !!currentWalletAddress && !initialEns },
  });

  // Cache ENS data
  useEffect(() => {
    if (currentWalletAddress && ensNameData) {
      cache.writeEns(currentWalletAddress, ensNameData);
    }
  }, [ensNameData, currentWalletAddress]);

  // Determine display name: ENS if available, otherwise truncated address
  const displayName = currentWalletAddress
    ? ensNameData ||
      initialEns ||
      `${currentWalletAddress.slice(0, 6)}...${currentWalletAddress.slice(-4)}`
    : "";

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
          <ul className="hidden sm:flex gap-6 text-slate-600 font-medium">
            <li
              className="hover:text-slate-900 cursor-pointer transition"
              onClick={() => onTabClick("sign")}
            >
              Sign
            </li>
            <li
              className="hover:text-slate-900 cursor-pointer transition"
              onClick={() => onTabClick("verify")}
            >
              Verify
            </li>
            <li
              className="hover:text-slate-900 cursor-pointer transition"
              onClick={() => onTabClick("encrypt")}
            >
              Encrypt
            </li>
            <li
              className="hover:text-slate-900 cursor-pointer transition"
              onClick={() => onTabClick("decrypt")}
            >
              Decrypt
            </li>
          </ul>

          {/* Mobile menu button */}
          <div className="sm:hidden">
            <button
              className="text-slate-600 hover:text-slate-900 p-2"
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

          {/* Show authenticated wallet or Auth side panel trigger */}
          <div className="flex items-center gap-2">
            {isAuthenticated && currentWalletAddress ? (
              <div
                className="flex items-center gap-2 px-2 sm:px-3 py-1 bg-slate-100 text-slate-700 rounded-md text-xs sm:text-sm font-medium cursor-pointer hover:bg-slate-200 transition"
                onClick={onAuthClick}
              >
                <span className="w-2 h-2 bg-slate-600 rounded-full"></span>
                <span>{displayName}</span>
              </div>
            ) : (
              <div
                className="hover:text-slate-900 cursor-pointer flex items-center gap-2 px-2 sm:px-3 py-1 text-slate-600 font-medium"
                onClick={onAuthClick}
              >
                <span>Auth</span>
                <span className="w-2 h-2 rounded-full bg-slate-300"></span>
              </div>
            )}
          </div>
        </div>

        {/* Mobile menu */}
        {isMobileMenuOpen && (
          <div className="sm:hidden absolute top-full left-0 right-0 bg-white border-b border-slate-200 shadow-sm z-10">
            <ul className="py-2">
              <li
                className="px-4 py-3 hover:bg-slate-50 cursor-pointer text-slate-600 font-medium"
                onClick={() => {
                  onTabClick("sign");
                  setIsMobileMenuOpen(false);
                }}
              >
                Sign
              </li>
              <li
                className="px-4 py-3 hover:bg-slate-50 cursor-pointer text-slate-600 font-medium"
                onClick={() => {
                  onTabClick("verify");
                  setIsMobileMenuOpen(false);
                }}
              >
                Verify
              </li>
              <li
                className="px-4 py-3 hover:bg-slate-50 cursor-pointer text-slate-600 font-medium"
                onClick={() => {
                  onTabClick("encrypt");
                  setIsMobileMenuOpen(false);
                }}
              >
                Encrypt
              </li>
              <li
                className="px-4 py-3 hover:bg-slate-50 cursor-pointer text-slate-600 font-medium"
                onClick={() => {
                  onTabClick("decrypt");
                  setIsMobileMenuOpen(false);
                }}
              >
                Decrypt
              </li>
            </ul>
          </div>
        )}
      </nav>
    </div>
  );
}
