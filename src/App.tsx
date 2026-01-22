// src/App.tsx
import { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { Signature } from "./components/Signature";
import { Verify } from "./components/Verify";
import { Encrypt } from "./components/Encrypt";
import { PasskeyAuth } from "./components/PasskeyAuth";
import { Decrypt } from "./components/Decrypt";

type TabType = "sign" | "verify" | "encrypt" | "decrypt";

function App() {
  const [activeTab, setActiveTab] = useState<TabType>("sign");
  const [isAuthPanelOpen, setIsAuthPanelOpen] = useState(false);

  // Handle ESC key to close auth panel
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsAuthPanelOpen(false);
      }
    };

    if (isAuthPanelOpen) {
      document.addEventListener("keydown", handleEscape);
      // Prevent body scroll when panel is open
      document.body.style.overflow = "hidden";
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      document.body.style.overflow = "unset";
    };
  }, [isAuthPanelOpen]);

  const renderComponent = () => {
    switch (activeTab) {
      case "sign":
        return <Signature />;
      case "verify":
        return <Verify />;
      case "encrypt":
        return <Encrypt />;
      case "decrypt":
        return <Decrypt />;
      default:
        return <Signature />;
    }
  };

  return (
    <div className="min-h-screen bg-slate-50 min-w-[300px]">
      <Navbar
        onTabClick={setActiveTab}
        onAuthClick={() => setIsAuthPanelOpen(true)}
      />

      {/* Auth Side Panel */}
      {isAuthPanelOpen && (
        <div className="fixed inset-0 z-50">
          {/* Click outside to close - no backdrop */}
          <div
            className="absolute inset-0"
            onClick={() => setIsAuthPanelOpen(false)}
          />

          {/* Side Panel */}
          <div className="absolute right-0 top-0 h-full w-full max-w-md bg-white shadow-xl transform transition-transform duration-300 ease-in-out">
            <div className="flex flex-col h-full max-h-screen overflow-hidden">
              {/* Auth Content - Full space without close button */}
              <div className="flex-1 overflow-y-auto">
                <PasskeyAuth />
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="flex-1">{renderComponent()}</div>
    </div>
  );
}

export default App;
