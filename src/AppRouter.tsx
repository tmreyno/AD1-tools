import { createSignal, Show } from "solid-js";
import App from "./App";
import { E01V3Test } from "./E01V3Test";
import { RawTest } from "./RawTest";
import "./AppRouter.css";

type Page = "main" | "e01v3" | "raw";

export function AppRouter() {
  const [currentPage, setCurrentPage] = createSignal<Page>("main");

  return (
    <div class="app-router">
      <nav class="app-nav">
        <div class="nav-brand">AD1 Tools</div>
        <div class="nav-links">
          <button
            class={currentPage() === "main" ? "active" : ""}
            onClick={() => setCurrentPage("main")}
          >
            Main App
          </button>
          <button
            class={currentPage() === "e01v3" ? "active" : ""}
            onClick={() => setCurrentPage("e01v3")}
          >
            E01 Test
          </button>
          <button
            class={currentPage() === "raw" ? "active" : ""}
            onClick={() => setCurrentPage("raw")}
          >
            Raw Test
          </button>
        </div>
      </nav>

      <div class="page-content">
        <Show when={currentPage() === "main"}>
          <App />
        </Show>
        <Show when={currentPage() === "e01v3"}>
          <E01V3Test />
        </Show>
        <Show when={currentPage() === "raw"}>
          <RawTest />
        </Show>
      </div>
    </div>
  );
}
