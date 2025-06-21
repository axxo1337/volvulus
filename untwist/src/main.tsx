import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import { ThemeProvider } from "./components/layout/ThemeProvider";
import ToggleTheme from "./components/ui/ToggleTheme";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ThemeProvider defaultTheme="system" storageKey="vite-ui-theme">
      <h1>Work in progress</h1>
      <ToggleTheme />
    </ThemeProvider>
  </StrictMode>
);
