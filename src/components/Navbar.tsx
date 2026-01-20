// src/components/Navbar.tsx
import { useAuth } from "../context/AuthContext";

type TabType = "auth" | "sign" | "verify" | "encrypt";

interface NavbarProps {
  onTabClick: (tab: TabType) => void;
}

export function Navbar({ onTabClick }: NavbarProps) {
  const { isAuthenticated, hasPasskeys, currentWalletAddress } = useAuth();

  return (
    <nav className="flex items-center justify-between px-8 py-4 border-b border-gray-200 bg-white">
      <div className="flex items-center gap-2 text-xl font-bold tracking-tight">
        <img
          src="/IB_icon.png"
          alt="App icon"
          className="w-10 h-10 object-contain"
        />
      </div>

      <div
        className="ap-8"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          width: "100%",
        }}
      >
        <div style={{ marginLeft: "40px" }}>
          <ul className="flex gap-6 text-gray-600 font-medium">
            <li
              className="hover:text-blue-600 cursor-pointer"
              onClick={() => onTabClick("sign")}
            >
              Sign
            </li>
            <li
              className="hover:text-blue-600 cursor-pointer"
              onClick={() => onTabClick("verify")}
            >
              Verify
            </li>
            <li
              className="hover:text-blue-600 cursor-pointer"
              onClick={() => onTabClick("encrypt")}
            >
              Encrypt
            </li>
          </ul>
        </div>

        {/* Show authenticated wallet or Auth tab with status */}
        <div className="flex items-center gap-2">
          {isAuthenticated && currentWalletAddress ? (
            <div
              className="flex items-center gap-2 px-3 py-1 bg-green-100 text-green-800 rounded-lg text-sm font-medium cursor-pointer hover:bg-green-200 transition"
              onClick={() => onTabClick("auth")}
            >
              <span className="w-2 h-2 bg-green-500 rounded-full"></span>
              {currentWalletAddress.slice(0, 6)}...
              {currentWalletAddress.slice(-4)}
            </div>
          ) : (
            <div
              className="hover:text-blue-600 cursor-pointer flex items-center gap-2 px-3 py-1 text-gray-600 font-medium"
              onClick={() => onTabClick("auth")}
            >
              Auth
              <span
                className={`w-2 h-2 rounded-full ${
                  hasPasskeys ? "bg-yellow-500" : "bg-gray-300"
                }`}
              ></span>
            </div>
          )}
        </div>
      </div>
    </nav>
  );
}
