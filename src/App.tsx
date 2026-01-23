// src/App.tsx
import { useState, useEffect, useRef } from "react";
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
  const [isMobile, setIsMobile] = useState(false);
  const isHandlingPopState = useRef(false);

  // Mobile detection
  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 768); // Tailwind md breakpoint
    };

    checkMobile();
    window.addEventListener("resize", checkMobile);

    return () => window.removeEventListener("resize", checkMobile);
  }, []);

  // Handle ESC key and back gesture to close auth panel
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setIsAuthPanelOpen(false);
      }
    };

    const handlePopState = () => {
      // Mark that we're handling a popstate event
      isHandlingPopState.current = true;
      setIsAuthPanelOpen(false);
    };

    if (isAuthPanelOpen) {
      document.addEventListener("keydown", handleEscape);
      window.addEventListener("popstate", handlePopState);
      // Prevent body scroll when panel is open
      document.body.style.overflow = "hidden";
      // Push state for back gesture support
      window.history.pushState({ panel: "auth" }, "");
    }

    return () => {
      document.removeEventListener("keydown", handleEscape);
      window.removeEventListener("popstate", handlePopState);
      document.body.style.overflow = "unset";
      // Only pop state if panel was manually closed (not through popstate)
      if (isAuthPanelOpen && !isHandlingPopState.current) {
        window.history.back();
      }
      // Reset the flag
      isHandlingPopState.current = false;
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
              {/* Close button - different positioning for desktop vs mobile */}
              <button
                onClick={() => setIsAuthPanelOpen(false)}
                className={`absolute top-5 z-10 p-1.5 bg-gray-200 border border-gray-300 rounded shadow-sm hover:bg-gray-300 hover:border-gray-400 transition-colors ${
                  isMobile ? "right-7" : "right-10"
                }`}
              >
                <svg
                  className="w-4 h-4 text-gray-800"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>

              {/* Auth Content */}
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
