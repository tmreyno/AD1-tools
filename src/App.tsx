import { For, Show, createMemo, createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import "./App.css";

type SegmentHeader = {
  signature: string;
  segment_index: number;
  segment_number: number;
  fragments_size: number;
  header_size: number;
};

type LogicalHeader = {
  signature: string;
  image_version: number;
  zlib_chunk_size: number;
  logical_metadata_addr: number;
  first_item_addr: number;
  data_source_name_length: number;
  ad_signature: string;
  data_source_name_addr: number;
  attrguid_footer_addr: number;
  locsguid_footer_addr: number;
  data_source_name: string;
};

type TreeEntry = {
  path: string;
  is_dir: boolean;
  size: number;
  item_type: number;
};

type VerifyEntry = {
  path: string;
  status: string;
};

type DiscoveredFile = {
  path: string;
  filename: string;
  container_type: string;
  size: number;
  segment_count?: number;
};

type Ad1Info = {
  segment: SegmentHeader;
  logical: LogicalHeader;
  item_count: number;
  tree?: TreeEntry[];
};

type E01Info = {
  format_version: string;
  segment_count: number;
  sector_count: number;
  bytes_per_sector: number;
  chunk_count: number;
  sectors_per_chunk: number;
  total_size: number;
  compression: string;
  case_number?: string;
  description?: string;
  examiner_name?: string;
  evidence_number?: string;
  notes?: string;
  acquiry_date?: string;
  system_date?: string;
  model?: string;
  serial_number?: string;
};

type L01Info = {
  format_version: number;
  case_info: string;
  examiner?: string;
  description?: string;
  file_count: number;
  total_size: number;
};

type ContainerInfo = {
  container: string;
  ad1?: Ad1Info | null;
  e01?: E01Info | null;
  l01?: L01Info | null;
  note?: string | null;
};

type StatusKind = "idle" | "working" | "ok" | "error";

type StatusState = {
  kind: StatusKind;
  message: string;
};

const defaultStatus: StatusState = {
  kind: "idle",
  message: "Ready",
};

function App() {
  const [inputPath, setInputPath] = createSignal("");
  const [outputDir, setOutputDir] = createSignal("");
  const [scanDir, setScanDir] = createSignal("");
  const [includeTree, setIncludeTree] = createSignal(true);
  const [info, setInfo] = createSignal<ContainerInfo | null>(null);
  const [tree, setTree] = createSignal<TreeEntry[]>([]);
  const [treeFilter, setTreeFilter] = createSignal("");
  const [verifyResults, setVerifyResults] = createSignal<VerifyEntry[]>([]);
  const [verifyFilter, setVerifyFilter] = createSignal("");
  const [discoveredFiles, setDiscoveredFiles] = createSignal<DiscoveredFile[]>([]);
  const [status, setStatus] = createSignal<StatusState>(defaultStatus);
  const [busy, setBusy] = createSignal(false);

  const filteredTree = createMemo(() => {
    const filter = treeFilter().trim().toLowerCase();
    if (!filter) return tree();
    return tree().filter((entry) => entry.path.toLowerCase().includes(filter));
  });

  const filteredVerify = createMemo(() => {
    const filter = verifyFilter().trim().toLowerCase();
    if (!filter) return verifyResults();
    return verifyResults().filter((entry) =>
      entry.path.toLowerCase().includes(filter),
    );
  });

  const verifySummary = createMemo(() => {
    const summary = { ok: 0, nok: 0, error: 0 };
    for (const item of verifyResults()) {
      if (item.status === "ok") summary.ok += 1;
      else if (item.status === "nok") summary.nok += 1;
      else if (item.status === "error") summary.error += 1;
    }
    return summary;
  });

  const setWorking = (message: string) => {
    setBusy(true);
    setStatus({ kind: "working", message });
  };

  const setError = (message: string) => {
    setBusy(false);
    setStatus({ kind: "error", message });
  };

  const setOk = (message: string) => {
    setBusy(false);
    setStatus({ kind: "ok", message });
  };

  const reset = () => {
    setInfo(null);
    setTree([]);
    setVerifyResults([]);
    setTreeFilter("");
    setVerifyFilter("");
    setStatus(defaultStatus);
  };

  const loadInfo = async (include: boolean) => {
    if (!inputPath().trim()) {
      setError("Add an AD1 file path first.");
      return;
    }
    setWorking(include ? "Loading info + tree" : "Loading info");
    try {
      const result = await invoke<ContainerInfo>("logical_info", {
        inputPath: inputPath(),
        includeTree: include,
      });
      setInfo(result);
      setTree(result.ad1?.tree ?? []);
      setOk("Info loaded");
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const runVerify = async (algorithm: "md5" | "sha1") => {
    if (!inputPath().trim()) {
      setError("Add an AD1 file path first.");
      return;
    }
    setWorking(`Verifying ${algorithm.toUpperCase()}`);
    try {
      const result = await invoke<VerifyEntry[]>("logical_verify", {
        inputPath: inputPath(),
        algorithm,
      });
      setVerifyResults(result);
      setOk(`${algorithm.toUpperCase()} verification complete`);
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const runExtract = async () => {
    if (!inputPath().trim()) {
      setError("Add an AD1 file path first.");
      return;
    }
    if (!outputDir().trim()) {
      setError("Set an output directory first.");
      return;
    }
    setWorking("Extracting files");
    try {
      await invoke("logical_extract", {
        inputPath: inputPath(),
        outputDir: outputDir(),
      });
      setOk("Extraction complete");
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const scanForFiles = async () => {
    if (!scanDir().trim()) {
      setError("Add a directory path to scan.");
      return;
    }
    setWorking("Scanning directory for forensic files");
    try {
      const result = await invoke<DiscoveredFile[]>("scan_directory", {
        dirPath: scanDir(),
      });
      setDiscoveredFiles(result);
      setOk(`Found ${result.length} forensic container file(s)`);
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const selectDiscoveredFile = (file: DiscoveredFile) => {
    setInputPath(file.path);
    setOk(`Selected: ${file.filename}`);
  };

  const browseInputFile = async () => {
    try {
      const selected = await open({
        title: "Select Input File",
        multiple: false,
        directory: false,
        filters: [
          {
            name: "Forensic Images",
            extensions: ["ad1", "e01", "l01", "E01", "E02", "E03", "E04", "E05", "E06", "E07", "E08"],
          },
          {
            name: "All Files",
            extensions: ["*"],
          },
        ],
      });
      if (selected) {
        setInputPath(selected);
        setOk(`Selected: ${selected}`);
      }
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const browseOutputDir = async () => {
    try {
      const selected = await open({
        title: "Select Output Directory",
        multiple: false,
        directory: true,
      });
      if (selected) {
        setOutputDir(selected);
        setOk(`Output directory: ${selected}`);
      }
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  const browseScanDir = async () => {
    try {
      const selected = await open({
        title: "Select Directory to Scan",
        multiple: false,
        directory: true,
      });
      if (selected) {
        setScanDir(selected);
        setOk(`Scan directory: ${selected}`);
      }
    } catch (err) {
      setError(normalizeError(err));
    }
  };

  return (
    <div class="app">
      <header class="hero">
        <div>
          <p class="eyebrow">LIBLFX</p>
          <h1>liblfx</h1>
          <p class="tagline">
            Rust-backed explorer for AccessData AD1 logical images.
          </p>
        </div>
        <div class="status">
          <span class={`badge ${status().kind}`}>{status().message}</span>
          <span class="status-meta">{busy() ? "Working" : "Idle"}</span>
        </div>
      </header>

      <div class="layout">
        <aside class="controls">
          <section class="card">
            <h2>Inputs</h2>
            <label class="field">
              <span>Input file path</span>
              <div class="input-with-button">
                <input
                  value={inputPath()}
                  onInput={(event) => setInputPath(event.currentTarget.value)}
                  placeholder="/path/to/image.ad1"
                />
                <button onClick={browseInputFile} disabled={busy()} class="browse-btn">
                  Browse...
                </button>
              </div>
            </label>
            <label class="field">
              <span>Output directory</span>
              <div class="input-with-button">
                <input
                  value={outputDir()}
                  onInput={(event) => setOutputDir(event.currentTarget.value)}
                  placeholder="/path/to/output"
                />
                <button onClick={browseOutputDir} disabled={busy()} class="browse-btn">
                  Browse...
                </button>
              </div>
            </label>
            <label class="toggle">
              <input
                type="checkbox"
                checked={includeTree()}
                onInput={(event) => setIncludeTree(event.currentTarget.checked)}
              />
              <span>Include tree in info scan</span>
            </label>
          </section>

          <section class="card">
            <h2>Directory Scan</h2>
            <label class="field">
              <span>Directory to scan</span>
              <div class="input-with-button">
                <input
                  value={scanDir()}
                  onInput={(event) => setScanDir(event.currentTarget.value)}
                  placeholder="/path/to/directory"
                />
                <button onClick={browseScanDir} disabled={busy()} class="browse-btn">
                  Browse...
                </button>
              </div>
            </label>
            <button disabled={busy()} onClick={scanForFiles} class="accent">
              Scan for Files
            </button>
          </section>

          <section class="card actions">
            <h2>Actions</h2>
            <div class="button-grid">
              <button disabled={busy()} onClick={() => loadInfo(false)}>
                Load Info
              </button>
              <button disabled={busy()} onClick={() => loadInfo(true)}>
                Load Tree
              </button>
              <button disabled={busy()} onClick={() => runVerify("md5")}
                class="accent">
                Verify MD5
              </button>
              <button disabled={busy()} onClick={() => runVerify("sha1")}
                class="accent">
                Verify SHA1
              </button>
              <button disabled={busy()} onClick={runExtract} class="accent">
                Extract Files
              </button>
              <button disabled={busy()} onClick={reset} class="ghost">
                Clear
              </button>
            </div>
          </section>

          <section class="card summary">
            <h2>Verify Summary</h2>
            <div class="summary-grid">
              <div>
                <span>OK</span>
                <strong>{verifySummary().ok}</strong>
              </div>
              <div>
                <span>NOK</span>
                <strong>{verifySummary().nok}</strong>
              </div>
              <div>
                <span>ERROR</span>
                <strong>{verifySummary().error}</strong>
              </div>
            </div>
            <p class="note">
              Hash checks read and decompress file data. Large images can take
              time.
            </p>
          </section>
        </aside>

        <section class="outputs">
          <section class="card">
            <h2>Image Info</h2>
            <Show when={info()} fallback={<p class="muted">No info loaded.</p>}>
              {(data) => (
                <>
                  <Show when={data().ad1}>
                    {(ad1) => (
                      <div class="info-grid">
                        <div>
                          <h3>Segment Header</h3>
                          <dl>
                            <InfoRow label="Signature" value={ad1().segment.signature} />
                            <InfoRow
                              label="Segment index"
                              value={ad1().segment.segment_index}
                            />
                            <InfoRow
                              label="Segment count"
                              value={ad1().segment.segment_number}
                            />
                            <InfoRow
                              label="Fragments size"
                              value={ad1().segment.fragments_size}
                            />
                            <InfoRow
                              label="Header size"
                              value={ad1().segment.header_size}
                            />
                          </dl>
                        </div>
                        <div>
                          <h3>Logical Header</h3>
                          <dl>
                            <InfoRow label="Signature" value={ad1().logical.signature} />
                            <InfoRow
                              label="Image version"
                              value={ad1().logical.image_version}
                            />
                            <InfoRow
                              label="Zlib chunk size"
                              value={ad1().logical.zlib_chunk_size}
                            />
                            <InfoRow
                              label="Metadata addr"
                              value={ad1().logical.logical_metadata_addr}
                            />
                            <InfoRow
                              label="First item addr"
                              value={ad1().logical.first_item_addr}
                            />
                            <InfoRow
                              label="Data source"
                              value={ad1().logical.data_source_name}
                            />
                            <InfoRow label="Item count" value={ad1().item_count} />
                          </dl>
                        </div>
                      </div>
                    )}
                  </Show>
                  
                  <Show when={data().e01}>
                    {(e01) => (
                      <div class="info-grid">
                        <div>
                          <h3>E01 (Expert Witness Format)</h3>
                          <dl>
                            <InfoRow label="Format" value={e01().format_version} />
                            <InfoRow label="Segments" value={e01().segment_count} />
                            <InfoRow label="Compression" value={e01().compression} />
                            <InfoRow label="Total Size" value={`${(e01().total_size / 1024 / 1024).toFixed(2)} MB`} />
                            <InfoRow label="Sector Count" value={e01().sector_count} />
                            <InfoRow label="Bytes/Sector" value={e01().bytes_per_sector} />
                            <InfoRow label="Sectors/Chunk" value={e01().sectors_per_chunk} />
                            <InfoRow label="Total Chunks" value={e01().chunk_count} />
                          </dl>
                        </div>
                        <div>
                          <h3>Case Information</h3>
                          <dl>
                            <Show when={e01().case_number}>
                              <InfoRow label="Case Number" value={e01().case_number!} />
                            </Show>
                            <Show when={e01().evidence_number}>
                              <InfoRow label="Evidence Number" value={e01().evidence_number!} />
                            </Show>
                            <Show when={e01().examiner_name}>
                              <InfoRow label="Examiner" value={e01().examiner_name!} />
                            </Show>
                            <Show when={e01().description}>
                              <InfoRow label="Description" value={e01().description!} />
                            </Show>
                            <Show when={e01().notes}>
                              <InfoRow label="Notes" value={e01().notes!} />
                            </Show>
                            <Show when={e01().acquiry_date}>
                              <InfoRow label="Acquired" value={e01().acquiry_date!} />
                            </Show>
                            <Show when={e01().system_date}>
                              <InfoRow label="System Date" value={e01().system_date!} />
                            </Show>
                            <Show when={e01().model}>
                              <InfoRow label="Model" value={e01().model!} />
                            </Show>
                            <Show when={e01().serial_number}>
                              <InfoRow label="Serial Number" value={e01().serial_number!} />
                            </Show>
                          </dl>
                        </div>
                      </div>
                    )}
                  </Show>
                  
                  <Show when={data().l01}>
                    {(l01) => (
                      <div class="info-grid">
                        <div>
                          <h3>L01 (Logical Evidence File)</h3>
                          <dl>
                            <InfoRow label="Format Version" value={l01().format_version} />
                            <InfoRow label="File Count" value={l01().file_count} />
                            <InfoRow label="Total Size" value={`${(l01().total_size / 1024 / 1024).toFixed(2)} MB`} />
                            <InfoRow label="Case Info" value={l01().case_info} />
                            <Show when={l01().examiner}>
                              <InfoRow label="Examiner" value={l01().examiner!} />
                            </Show>
                            <Show when={l01().description}>
                              <InfoRow label="Description" value={l01().description!} />
                            </Show>
                          </dl>
                        </div>
                      </div>
                    )}
                  </Show>
                  
                  <Show when={!data().ad1 && !data().e01 && !data().l01}>
                    <div class="muted">
                      <p>{data().note ?? "Unsupported logical container."}</p>
                      <p>Detected container: {data().container}</p>
                    </div>
                  </Show>
                </>
              )}
            </Show>
          </section>

          <section class="card">
            <h2>Discovered Files</h2>
            <Show
              when={discoveredFiles().length > 0}
              fallback={<p class="muted">Scan a directory to find forensic container files.</p>}
            >
              <ul class="list">
                <For each={discoveredFiles()}>
                  {(file) => (
                    <li 
                      class="clickable" 
                      onClick={() => selectDiscoveredFile(file)}
                      title={file.path}
                    >
                      <span class="dot file" />
                      <span class="path">{file.filename}</span>
                      <span class="size">{file.container_type}</span>
                      <span class="size">{formatBytes(file.size)}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>

          <section class="card">
            <div class="card-head">
              <h2>Tree</h2>
              <input
                class="filter"
                value={treeFilter()}
                onInput={(event) => setTreeFilter(event.currentTarget.value)}
                placeholder="Filter path"
              />
            </div>
            <Show
              when={filteredTree().length > 0}
              fallback={<p class="muted">Tree entries appear here.</p>}
            >
              <ul class="list">
                <For each={filteredTree()}>
                  {(entry) => (
                    <li>
                      <span class={`dot ${entry.is_dir ? "dir" : "file"}`} />
                      <span class="path">{entry.path}</span>
                      <span class="size">
                        {entry.is_dir ? "dir" : formatBytes(entry.size)}
                      </span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>

          <section class="card">
            <div class="card-head">
              <h2>Verify Results</h2>
              <input
                class="filter"
                value={verifyFilter()}
                onInput={(event) => setVerifyFilter(event.currentTarget.value)}
                placeholder="Filter file"
              />
            </div>
            <Show
              when={filteredVerify().length > 0}
              fallback={<p class="muted">No verification results yet.</p>}
            >
              <ul class="list">
                <For each={filteredVerify()}>
                  {(entry) => (
                    <li class={`status-${entry.status}`}>
                      <span class="dot" />
                      <span class="path">{entry.path}</span>
                      <span class="size">{entry.status.toUpperCase()}</span>
                    </li>
                  )}
                </For>
              </ul>
            </Show>
          </section>
        </section>
      </div>
    </div>
  );
}

function InfoRow(props: { label: string; value: string | number }) {
  return (
    <div class="info-row">
      <dt>{props.label}</dt>
      <dd>{props.value}</dd>
    </div>
  );
}

function formatBytes(value: number) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1);
  const size = value / Math.pow(1024, index);
  return `${size.toFixed(size < 10 ? 2 : 1)} ${units[index]}`;
}

function normalizeError(err: unknown) {
  if (!err) return "Unknown error";
  if (typeof err === "string") return err;
  if (typeof err === "object" && "message" in err) {
    return String((err as { message: string }).message);
  }
  return JSON.stringify(err);
}

export default App;
