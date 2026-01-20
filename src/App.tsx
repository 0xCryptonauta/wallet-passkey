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
    <div className="min-h-screen bg-gray-50">
      <Navbar onTabClick={setActiveTab} />
      {renderComponent()}
    </div>
  );
}

export default App;
