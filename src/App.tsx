// src/App.tsx
import { useState } from "react";
import { Navbar } from "./components/Navbar";
import { Signature } from "./components/Signature";
import { Verify } from "./components/Verify";
import { Encrypt } from "./components/Encrypt";

type TabType = "sign" | "verify" | "encrypt";

function App() {
  const [activeTab, setActiveTab] = useState<TabType>("sign");

  const renderComponent = () => {
    switch (activeTab) {
      case "sign":
        return <Signature />;
      case "verify":
        return <Verify />;
      case "encrypt":
        return <Encrypt />;
      default:
        return <Signature />;
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
