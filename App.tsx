import React, { useState, useEffect, useCallback, useRef } from "react";
import type { Step, Network, Client } from "./types";
import { STEPS } from "./constants";
import { simulationService } from "./services/simulationService";
import { realService } from "./services/realService";
import StepIndicator from "./components/StepIndicator";
import Card from "./components/Card";
import Button from "./components/Button";
import TerminalOutput from "./components/TerminalOutput";
import Disclaimer from "./components/Disclaimer";
import InterfaceSelector from "./components/InterfaceSelector";
import NetworkScanner from "./components/NetworkScanner";
import HandshakeCapture from "./components/HandshakeCapture";
import Cracker from "./components/Cracker";
import Results from "./components/Results";

const App: React.FC = () => {
  const [currentStep, setCurrentStep] = useState<Step>("SELECT_INTERFACE");
  const [interfaces, setInterfaces] = useState<string[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string | null>(
    null
  );
  const [monitorInterface, setMonitorInterface] = useState<string | null>(null);
  const [networks, setNetworks] = useState<Network[]>([]);
  const [clients, setClients] = useState<Client[]>([]);
  const [targetNetwork, setTargetNetwork] = useState<Network | null>(null);
  const [handshakeCaptured, setHandshakeCaptured] = useState(false);
  const [crackedPassword, setCrackedPassword] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [terminalOutput, setTerminalOutput] = useState<string[]>([
    "Welcome to Wi-Fi Security Tool Simulator.",
  ]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const appendOutput = useCallback((lines: string | string[]) => {
    const newLines = Array.isArray(lines) ? lines : [lines];
    setTerminalOutput((prev) => [...prev, ...newLines]);
  }, []);

  useEffect(() => {
    appendOutput("Fetching available wireless interfaces...");
    (async () => {
      const useReal = Boolean(
        (import.meta as any).env?.VITE_USE_REAL === "true" ||
          (import.meta as any).env?.VITE_COMMAND_SERVER_URL
      );
      const svc = useReal ? realService : simulationService;
      const data = await svc.getNetworkInterfaces();
      setInterfaces(data.interfaces);
      appendOutput(`Found interfaces: ${data.interfaces.join(", ")}`);
      appendOutput(data.output);
    })();
  }, [appendOutput]);

  useEffect(() => {
    const runAutoSteps = async () => {
      // Step 3: Auto-capture handshake
      if (
        currentStep === "CAPTURING" &&
        targetNetwork &&
        monitorInterface &&
        !handshakeCaptured
      ) {
        setIsLoading(true);
        appendOutput(
          `[AUTO] Starting handshake capture for ${targetNetwork.essid}...`
        );

        const useReal = Boolean(
          (import.meta as any).env?.VITE_USE_REAL === "true" ||
            (import.meta as any).env?.VITE_COMMAND_SERVER_URL
        );
        const svc = useReal ? realService : simulationService;
        const captureResult = await svc.captureHandshake(targetNetwork);
        appendOutput(captureResult.output);

        if (captureResult.captured) {
          setHandshakeCaptured(true);
          appendOutput("[AUTO] WPA Handshake captured successfully!");
          setCurrentStep("CRACKING");
          return;
        }

        appendOutput(
          "[AUTO] Handshake not captured naturally. Attempting deauthentication..."
        );
        const targetClients = simulationService.getMockClients(
          targetNetwork.bssid
        );

        if (targetClients.length > 0) {
          const clientToDeauth = targetClients[0];
          appendOutput(
            `[AUTO] Sending deauthentication packets to ${clientToDeauth.mac}...`
          );
          const useReal2 = Boolean(
            (import.meta as any).env?.VITE_USE_REAL === "true" ||
              (import.meta as any).env?.VITE_COMMAND_SERVER_URL
          );
          const svc2 = useReal2 ? realService : simulationService;
          const deauthResult = await svc2.forceHandshake(
            targetNetwork,
            clientToDeauth,
            monitorInterface
          );
          appendOutput(deauthResult.output);
          setHandshakeCaptured(true);
          appendOutput("[AUTO] WPA Handshake captured via deauth!");
          setCurrentStep("CRACKING");
        } else {
          appendOutput(
            "[AUTO] No clients found for deauthentication. Cannot proceed."
          );
          setIsLoading(false);
        }
      }
      // Step 4: Auto-crack password
      else if (
        currentStep === "CRACKING" &&
        targetNetwork &&
        !crackedPassword
      ) {
        if (!isLoading) setIsLoading(true);

        const mockWordlistName = "rockyou.txt";
        appendOutput(
          `[AUTO] Starting offline dictionary attack with default wordlist: ${mockWordlistName}`
        );

        const useReal3 = Boolean(
          (import.meta as any).env?.VITE_USE_REAL === "true" ||
            (import.meta as any).env?.VITE_COMMAND_SERVER_URL
        );
        const svc3 = useReal3 ? realService : simulationService;
        const result = await svc3.crackPassword(
          targetNetwork,
          mockWordlistName
        );
        appendOutput(result.output);

        if (result.password) {
          setCrackedPassword(result.password);
          appendOutput(`KEY FOUND! [ ${result.password} ]`);
          setCurrentStep("DONE");
        } else {
          appendOutput("Password not found in the default wordlist.");
        }
        setIsLoading(false);
      }
    };

    runAutoSteps();
  }, [
    currentStep,
    targetNetwork,
    monitorInterface,
    handshakeCaptured,
    crackedPassword,
    appendOutput,
    isLoading,
  ]);

  const handleReset = () => {
    setCurrentStep("SELECT_INTERFACE");
    setSelectedInterface(null);
    setMonitorInterface(null);
    setNetworks([]);
    setClients([]);
    setTargetNetwork(null);
    setHandshakeCaptured(false);
    setCrackedPassword(null);
    setIsLoading(false);
    setTerminalOutput([
      "Simulator reset. Please select a wireless interface to begin.",
    ]);
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-gray-200 font-mono p-4 sm:p-6 lg:p-8">
      <div className="max-w-7xl mx-auto">
        <header className="text-center mb-8">
          <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold text-green-400">
            Wi-Fi Security Tool Simulator
          </h1>
          <p className="text-gray-400 mt-2">
            An educational walkthrough of network auditing
          </p>
        </header>

        <Disclaimer />

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          <div className="lg:col-span-3">
            <StepIndicator currentStep={currentStep} />
          </div>

          <main className="lg:col-span-9">
            <Card>
              {currentStep === "SELECT_INTERFACE" && (
                <InterfaceSelector
                  interfaces={interfaces}
                  selectedInterface={selectedInterface}
                  setSelectedInterface={setSelectedInterface}
                  isLoading={isLoading}
                  onStartMonitorMode={async () => {
                    if (!selectedInterface) return;
                    setIsLoading(true);
                    appendOutput(
                      `Starting monitor mode on ${selectedInterface}...`
                    );
                    const useReal4 = Boolean(
                      (import.meta as any).env?.VITE_USE_REAL === "true" ||
                        (import.meta as any).env?.VITE_COMMAND_SERVER_URL
                    );
                    const svc4 = useReal4 ? realService : simulationService;
                    const result = await svc4.startMonitorMode(
                      selectedInterface
                    );
                    appendOutput(result.output);
                    setMonitorInterface(result.monitorInterface);
                    setIsLoading(false);
                    setCurrentStep("SCANNING");
                  }}
                />
              )}

              {currentStep === "SCANNING" && monitorInterface && (
                <NetworkScanner
                  monitorInterface={monitorInterface}
                  networks={networks}
                  isLoading={isLoading}
                  onScan={async () => {
                    setIsLoading(true);
                    setNetworks([]);
                    appendOutput(
                      `Scanning for networks on ${monitorInterface}...`
                    );
                    await simulationService.scanForNetworks(
                      monitorInterface,
                      (newNetworks, output) => {
                        setNetworks((prev) =>
                          [...prev, ...newNetworks].filter(
                            (v, i, a) =>
                              a.findIndex((t) => t.bssid === v.bssid) === i
                          )
                        );
                        appendOutput(output);
                      }
                    );
                    setIsLoading(false);
                  }}
                  onSelectNetwork={(network) => {
                    setTargetNetwork(network);
                    appendOutput(
                      `Target network selected: ${network.essid} (${network.bssid}) on channel ${network.channel}.`
                    );
                    setCurrentStep("CAPTURING");
                  }}
                />
              )}

              {currentStep === "CAPTURING" && targetNetwork && (
                <HandshakeCapture
                  targetNetwork={targetNetwork}
                  handshakeCaptured={handshakeCaptured}
                  isLoading={isLoading}
                />
              )}

              {currentStep === "CRACKING" && targetNetwork && (
                <Cracker isLoading={isLoading} />
              )}

              {currentStep === "DONE" && targetNetwork && crackedPassword && (
                <Results
                  targetNetwork={targetNetwork}
                  crackedPassword={crackedPassword}
                  onReset={handleReset}
                />
              )}
            </Card>

            <div className="mt-8">
              <TerminalOutput output={terminalOutput} />
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};

export default App;
