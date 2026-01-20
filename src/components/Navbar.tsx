// src/components/Navbar.tsx
import { Account } from "./Account";

type TabType = "sign" | "verify" | "encrypt";

interface NavbarProps {
  onTabClick: (tab: TabType) => void;
}

export function Navbar({ onTabClick }: NavbarProps) {
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

        <Account />
      </div>
    </nav>
  );
}
