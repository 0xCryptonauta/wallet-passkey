// src/App.tsx
import { useState } from "react";
import { Navbar } from "./components/Navbar";
import { Signature } from "./components/Signature";
import { Verify } from "./components/Verify";
import { Encrypt } from "./components/Encrypt";
import { PasskeyAuth } from "./components/PasskeyAuth";

type TabType = "auth" | "sign" | "verify" | "encrypt";

function App() {
  const [activeTab, setActiveTab] = useState<TabType>("sign");

  const renderComponent = () => {
    switch (activeTab) {
      case "auth":
        return <PasskeyAuth />;
      case "sign":
        return <Signature />;
      case "verify":
        return <Verify />;
      case "encrypt":
        return <Encrypt />;
      default:
        return <PasskeyAuth />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 min-w-[300px]">
      <Navbar onTabClick={setActiveTab} />
      <div className="flex-1">{renderComponent()}</div>
    </div>
  );
}

export default App;
