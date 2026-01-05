import { Component, For, Show } from 'solid-js';
import type { 
  ProcessedDatabase, AxiomCaseInfo, ArtifactCategorySummary,
  AxiomKeywordFile
} from '../types/processed';
import type { DetailViewType } from '../hooks/useProcessedDatabases';
import { ellipsePath, getDbTypeName, getCategoryIcon, formatSize, formatDate } from '../utils/processed';

/** Detail view types for processed databases - re-export from hook */
export type ProcessedDetailView = DetailViewType;

interface ProcessedDetailPanelProps {
  database: ProcessedDatabase | null;
  caseInfo: AxiomCaseInfo | null;
  categories: ArtifactCategorySummary[];
  loading?: boolean;
  /** External detail view from manager (overrides internal state) */
  detailView?: DetailViewType;
  /** Callback when view changes internally */
  onDetailViewChange?: (view: DetailViewType) => void;
}

const ProcessedDetailPanel: Component<ProcessedDetailPanelProps> = (props) => {
  // Use external detailView - navigation is handled in the left panel
  const detailView = () => props.detailView ?? { type: 'case' };

  // Reset view when database changes
  const db = () => props.database;
  const caseInfo = () => props.caseInfo;
  const categories = () => props.categories || [];

  return (
    <div class="flex flex-col h-full bg-bg text-txt">
      <Show when={!db()}>
        <div class="flex flex-col items-center justify-center h-full gap-3 opacity-60 p-10 text-center">
          <div class="text-5xl">📊</div>
          <h3 class="m-0 text-lg font-medium text-txt-muted">No Database Selected</h3>
          <p class="m-0 text-base text-txt-faint">Select a processed database from the left panel to view details</p>
        </div>
      </Show>

      <Show when={db()}>
        {/* Loading indicator */}
        <Show when={props.loading}>
          <div class="absolute inset-0 flex items-center justify-center gap-2 bg-bg/80 z-10">
            <span class="animate-spin-slow">⏳</span>
            <span>Loading...</span>
          </div>
        </Show>

        {/* Detail Content - full width, no sidebar */}
        <div class="flex-1 overflow-auto p-0">
          {/* Case Report View */}
          <Show when={detailView()?.type === 'case'}>
            <div class="p-6 max-w-[900px]">
              <h2 class="text-xl font-semibold mb-6 text-txt flex items-center gap-2.5">📋 Case Report</h2>
              
              {/* Case Information Section */}
              <section class="mb-7 pb-6 border-b border-border">
                <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Case Information</h3>
                <div class="grid grid-cols-2 gap-3.5">
                  <div class="flex flex-col gap-1">
                    <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Case Name</span>
                    <span class="text-base text-txt break-words">{caseInfo()?.case_name || db()?.case_name || db()?.name || 'N/A'}</span>
                  </div>
                  <Show when={caseInfo()?.case_number}>
                    <div class="flex flex-col gap-1">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Case Number</span>
                      <span class="text-base text-txt break-words">{caseInfo()?.case_number}</span>
                    </div>
                  </Show>
                  <Show when={caseInfo()?.case_type}>
                    <div class="flex flex-col gap-1">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Case Type</span>
                      <span class="text-base text-txt break-words">{caseInfo()?.case_type}</span>
                    </div>
                  </Show>
                  <Show when={caseInfo()?.description}>
                    <div class="flex flex-col gap-1 col-span-2">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Description</span>
                      <span class="text-base text-txt break-words">{caseInfo()?.description}</span>
                    </div>
                  </Show>
                </div>
              </section>
              
              {/* Examiner Information Section */}
              <section class="mb-7 pb-6 border-b border-border">
                  <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Examiner Information</h3>
                  <div class="grid grid-cols-2 gap-3.5">
                    <div class="flex flex-col gap-1">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Examiner</span>
                      <span class="text-base text-txt break-words">{caseInfo()?.examiner || db()?.examiner || 'N/A'}</span>
                    </div>
                    <Show when={caseInfo()?.agency}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Agency</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.agency}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.user}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">User Account</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.user}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.host_name}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Workstation</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.host_name}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.operating_system}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Operating System</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.operating_system}</span>
                      </div>
                    </Show>
                  </div>
                </section>
                
                {/* Processing Information Section */}
                <section class="mb-7 pb-6 border-b border-border">
                  <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Processing Details</h3>
                  <div class="grid grid-cols-2 gap-3.5">
                    <div class="flex flex-col gap-1">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Tool</span>
                      <span class="text-base text-txt break-words">{getDbTypeName(db()?.db_type || 'Unknown')}</span>
                    </div>
                    <Show when={caseInfo()?.axiom_version || db()?.version}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Version</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.axiom_version || db()?.version}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.search_start}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Processing Started</span>
                        <span class="text-base text-txt break-words">{formatDate(caseInfo()?.search_start)}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.search_end}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Processing Ended</span>
                        <span class="text-base text-txt break-words">{formatDate(caseInfo()?.search_end)}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.search_duration}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Duration</span>
                        <span class="text-base text-txt break-words">{caseInfo()?.search_duration}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.search_outcome}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Outcome</span>
                        <span class={`text-base break-words ${caseInfo()?.search_outcome?.toLowerCase() === 'completed' ? 'text-success' : 'text-error'}`}>
                          {caseInfo()?.search_outcome}
                        </span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.created || db()?.created_date}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Created</span>
                        <span class="text-base text-txt break-words">{formatDate(caseInfo()?.created || db()?.created_date)}</span>
                      </div>
                    </Show>
                    <Show when={caseInfo()?.modified}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Last Modified</span>
                        <span class="text-base text-txt break-words">{formatDate(caseInfo()?.modified)}</span>
                      </div>
                    </Show>
                  </div>
                </section>
                
                {/* Statistics Summary */}
                <section class="mb-7 pb-6 border-b border-border">
                  <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Statistics Summary</h3>
                  <div class="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-3.5">
                    <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                      <span class="text-2xl font-semibold text-accent">{caseInfo()?.total_artifacts?.toLocaleString() || 0}</span>
                      <span class="text-xs uppercase tracking-wide text-txt-faint">Total Artifacts</span>
                    </div>
                    <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                      <span class="text-2xl font-semibold text-accent">{caseInfo()?.evidence_sources?.length || 0}</span>
                      <span class="text-xs uppercase tracking-wide text-txt-faint">Evidence Sources</span>
                    </div>
                    <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                      <span class="text-2xl font-semibold text-accent">{caseInfo()?.keyword_info?.keywords_entered || 0}</span>
                      <span class="text-xs uppercase tracking-wide text-txt-faint">Keywords</span>
                    </div>
                    <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                      <span class="text-2xl font-semibold text-accent">{caseInfo()?.search_results?.length || categories().length || 0}</span>
                      <span class="text-xs uppercase tracking-wide text-txt-faint">Artifact Types</span>
                    </div>
                  </div>
                </section>
                
                {/* File Location */}
                <section class="mb-7 pb-6 border-b border-border last:border-b-0 last:mb-0">
                  <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">File Location</h3>
                  <div class="grid grid-cols-2 gap-3.5">
                    <div class="flex flex-col gap-1 col-span-2">
                      <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Database Path</span>
                      <span class="text-sm text-txt font-mono bg-bg-panel px-3 py-2 rounded overflow-x-auto whitespace-nowrap" title={db()?.path}>{db()?.path}</span>
                    </div>
                    <Show when={db()?.total_size}>
                      <div class="flex flex-col gap-1">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Database Size</span>
                        <span class="text-base text-txt break-words">{formatSize(db()?.total_size)}</span>
                      </div>
                    </Show>
                  </div>
                </section>
              </div>
            </Show>

            {/* Evidence View */}
            <Show when={detailView()?.type === 'evidence'}>
              <div class="p-6 max-w-[900px]">
                <h2 class="text-xl font-semibold mb-6 text-txt flex items-center gap-2.5">📁 Evidence Sources</h2>
                <div class="flex flex-col gap-4">
                  <For each={caseInfo()?.evidence_sources || []}>
                    {(source, idx) => (
                      <div class="bg-bg-panel rounded-lg border border-border overflow-hidden">
                        <div class="flex items-center gap-2.5 px-4 py-3 bg-bg-card border-b border-border">
                          <span class="text-xs font-semibold text-accent bg-accent-soft px-2 py-0.5 rounded-full">#{idx() + 1}</span>
                          <span class="flex-1 font-medium text-sm overflow-hidden text-ellipsis whitespace-nowrap" title={source.name}>{ellipsePath(source.name, 50)}</span>
                          <Show when={source.evidence_number}>
                            <span class="text-sm text-txt-faint">[{source.evidence_number}]</span>
                          </Show>
                        </div>
                        <div class="grid grid-cols-2 gap-2.5 p-4">
                          <Show when={source.source_type}>
                            <div class="flex flex-col gap-0.5 text-sm">
                              <span class="text-2xs text-txt-faint uppercase">Type:</span>
                              <span class="text-sm text-txt">{source.source_type}</span>
                            </div>
                          </Show>
                          <Show when={source.path}>
                            <div class="flex flex-col gap-0.5 text-sm col-span-2">
                              <span class="text-2xs text-txt-faint uppercase">Path:</span>
                              <span class="text-sm text-txt" title={source.path}>{ellipsePath(source.path || '', 60)}</span>
                            </div>
                          </Show>
                          <Show when={source.hash}>
                            <div class="flex flex-col gap-0.5 text-sm">
                              <span class="text-2xs text-txt-faint uppercase">Hash:</span>
                              <span class="text-sm text-txt font-mono">{source.hash}</span>
                            </div>
                          </Show>
                          <Show when={source.size}>
                            <div class="flex flex-col gap-0.5 text-sm">
                              <span class="text-2xs text-txt-faint uppercase">Size:</span>
                              <span class="text-sm text-txt">{formatSize(source.size)}</span>
                            </div>
                          </Show>
                          <Show when={source.search_types && source.search_types.length > 0}>
                            <div class="flex flex-col gap-0.5 text-sm col-span-2">
                              <span class="text-2xs text-txt-faint uppercase">Search Types:</span>
                              <span class="text-sm text-txt">{source.search_types.join(', ')}</span>
                            </div>
                          </Show>
                        </div>
                      </div>
                    )}
                  </For>
                </div>
              </div>
            </Show>

            {/* Keywords Overview View */}
            <Show when={detailView()?.type === 'keywords'}>
              {(() => {
                const allKeywords = () => caseInfo()?.keyword_info?.keywords || [];
                const manualKeywords = () => allKeywords().filter(kw => !kw.from_file);
                const fileKeywords = () => allKeywords().filter(kw => kw.from_file);
                const regexKeywords = () => allKeywords().filter(kw => kw.is_regex);
                
                return (
                  <div class="p-6 max-w-[900px]">
                    <h2 class="text-xl font-semibold mb-6 text-txt flex items-center gap-2.5">🔑 Keyword Search Configuration</h2>
                    
                    {/* Keyword Summary */}
                    <section class="mb-7 pb-6 border-b border-border">
                      <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Summary</h3>
                      <div class="grid grid-cols-[repeat(auto-fit,minmax(140px,1fr))] gap-3.5">
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{allKeywords().length.toLocaleString()}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">Total Keywords</span>
                        </div>
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{manualKeywords().length.toLocaleString()}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">Manual Entry</span>
                        </div>
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{fileKeywords().length.toLocaleString()}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">From Files</span>
                        </div>
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{regexKeywords().length.toLocaleString()}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">Regex Patterns</span>
                        </div>
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{caseInfo()?.keyword_info?.keyword_files?.length || 0}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">Keyword Files</span>
                        </div>
                        <div class="bg-bg-panel rounded-lg p-4 text-center flex flex-col gap-1.5 border border-border">
                          <span class="text-2xl font-semibold text-accent">{caseInfo()?.keyword_info?.privileged_content_keywords?.length || 0}</span>
                          <span class="text-xs uppercase tracking-wide text-txt-faint">Privileged Terms</span>
                        </div>
                      </div>
                    </section>
                    
                    <Show when={caseInfo()?.keyword_info?.privileged_content_mode}>
                      <div class="flex flex-col gap-1 mb-4">
                        <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Privileged Content Mode:</span>
                        <span class="text-base text-txt">{caseInfo()?.keyword_info?.privileged_content_mode}</span>
                      </div>
                    </Show>
                    
                    {/* All Keywords Table */}
                    <Show when={allKeywords().length > 0}>
                      <section class="mb-7 pb-6 border-b border-border">
                        <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">All Keywords ({allKeywords().length.toLocaleString()})</h3>
                        <div class="bg-bg-panel rounded-lg border border-border overflow-hidden max-h-[500px] overflow-y-auto">
                          <table class="w-full border-collapse text-base">
                            <thead class="sticky top-0 z-[1]">
                              <tr>
                                <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[50px]">#</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border min-w-[200px]">Keyword</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[100px]">Type</th>
                                <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[80px]">Case</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[140px]">Source</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[150px]">Encodings</th>
                              </tr>
                            </thead>
                            <tbody>
                              <For each={allKeywords()}>
                                {(kw, idx) => (
                                  <tr class="hover:bg-white/[0.03] border-b border-white/5 last:border-b-0">
                                    <td class="px-3 py-2 text-center text-txt-faint font-mono text-xs">{idx() + 1}</td>
                                    <td class="px-3 py-2">
                                      <code class={`inline-block bg-bg px-2 py-0.5 rounded font-mono text-sm break-all max-w-[400px] ${kw.is_regex ? 'bg-warning-soft text-warning border border-warning/30' : ''}`}>{kw.value}</code>
                                    </td>
                                    <td class="px-3 py-2 text-sm">{kw.is_regex ? '🔣 Regex' : '🔤 Plain'}</td>
                                    <td class="px-3 py-2 text-center">{kw.is_case_sensitive ? 'Yes' : 'No'}</td>
                                    <td class="px-3 py-2 text-sm overflow-hidden text-ellipsis whitespace-nowrap">
                                      {kw.from_file ? (
                                        <span title={kw.file_name || 'Unknown file'}>📄 {kw.file_name || 'File'}</span>
                                      ) : (
                                        <span>✍️ Manual</span>
                                      )}
                                    </td>
                                    <td class="px-3 py-2 text-xs text-txt-muted">
                                      {kw.encoding_types.length > 0 ? kw.encoding_types.join(', ') : 'Default'}
                                    </td>
                                  </tr>
                                )}
                              </For>
                            </tbody>
                          </table>
                        </div>
                      </section>
                    </Show>
                    
                    {/* Privileged Content Keywords */}
                    <Show when={caseInfo()?.keyword_info?.privileged_content_keywords && caseInfo()!.keyword_info!.privileged_content_keywords.length > 0}>
                      <section class="mb-7 pb-6 border-b border-border last:border-b-0 last:mb-0">
                        <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">⚖️ Privileged Content Keywords ({caseInfo()!.keyword_info!.privileged_content_keywords.length})</h3>
                        <div class="bg-bg-panel rounded-lg border border-border overflow-hidden max-h-[500px] overflow-y-auto">
                          <table class="w-full border-collapse text-base">
                            <thead class="sticky top-0 z-[1]">
                              <tr>
                                <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[50px]">#</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border min-w-[200px]">Keyword</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[100px]">Type</th>
                                <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[120px]">Tag/Category</th>
                              </tr>
                            </thead>
                            <tbody>
                              <For each={caseInfo()?.keyword_info?.privileged_content_keywords || []}>
                                {(kw, idx) => (
                                  <tr class="hover:bg-white/[0.03] border-b border-white/5 last:border-b-0">
                                    <td class="px-3 py-2 text-center text-txt-faint font-mono text-xs">{idx() + 1}</td>
                                    <td class="px-3 py-2">
                                      <code class={`inline-block bg-bg px-2 py-0.5 rounded font-mono text-sm break-all max-w-[400px] ${kw.is_regex ? 'bg-warning-soft text-warning border border-warning/30' : ''}`}>{kw.value}</code>
                                    </td>
                                    <td class="px-3 py-2 text-sm">{kw.is_regex ? '🔣 Regex' : '🔤 Plain'}</td>
                                    <td class="px-3 py-2 text-sm text-txt-muted">{kw.file_name || '—'}</td>
                                  </tr>
                                )}
                              </For>
                            </tbody>
                          </table>
                        </div>
                      </section>
                    </Show>
                  </div>
                );
              })()}
            </Show>

            {/* Keyword File Detail View */}
            <Show when={detailView()?.type === 'keyword-file'}>
              {(() => {
                const view = detailView() as { type: 'keyword-file'; file: AxiomKeywordFile };
                const file = view?.file;
                // Find keywords from this file - check both exact match and case-insensitive
                const fileKeywords = () => {
                  const keywords = caseInfo()?.keyword_info?.keywords || [];
                  const fileName = file?.file_name;
                  if (!fileName) return [];
                  
                  return keywords.filter(kw => 
                    kw.from_file && kw.file_name && (
                      kw.file_name === fileName ||
                      kw.file_name.toLowerCase() === fileName.toLowerCase()
                    )
                  );
                };
                
                // Group keywords by type (regex vs plain)
                const regexKeywords = () => fileKeywords().filter(kw => kw.is_regex);
                const plainKeywords = () => fileKeywords().filter(kw => !kw.is_regex);
                
                return (
                  <div class="p-6 max-w-[900px]">
                    <h2 class="text-xl font-semibold mb-6 text-txt flex items-center gap-2.5">📄 Keyword File Details</h2>
                    
                    <section class="mb-7 pb-6 border-b border-border">
                      <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">File Information</h3>
                      <div class="grid grid-cols-2 gap-3.5">
                        <div class="flex flex-col gap-1 col-span-2">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">File Name</span>
                          <span class="text-base text-txt break-words">{file?.file_name}</span>
                        </div>
                        <div class="flex flex-col gap-1 col-span-2">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Full Path</span>
                          <span class="text-sm text-txt font-mono bg-bg-panel px-3 py-2 rounded overflow-x-auto whitespace-nowrap" title={file?.file_path}>{file?.file_path}</span>
                        </div>
                        <div class="flex flex-col gap-1">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Keywords Count</span>
                          <span class="text-base text-txt break-words">{file?.record_count.toLocaleString()}</span>
                        </div>
                        <div class="flex flex-col gap-1">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Found in Case</span>
                          <span class="text-base text-txt break-words">{fileKeywords().length.toLocaleString()}</span>
                        </div>
                        <div class="flex flex-col gap-1">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Status</span>
                          <span class={`text-base break-words ${file?.enabled ? 'text-success' : 'text-txt-faint'}`}>
                            {file?.enabled ? '✓ Enabled' : '✗ Disabled'}
                          </span>
                        </div>
                        <div class="flex flex-col gap-1">
                          <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Case Sensitive</span>
                          <span class="text-base text-txt break-words">{file?.is_case_sensitive ? 'Yes' : 'No'}</span>
                        </div>
                        <Show when={file?.date_added}>
                          <div class="flex flex-col gap-1">
                            <span class="text-xs font-medium text-txt-faint uppercase tracking-wide">Date Added</span>
                            <span class="text-base text-txt break-words">{formatDate(file?.date_added)}</span>
                          </div>
                        </Show>
                      </div>
                    </section>
                    
                    {/* Complete keyword list from this file */}
                    <Show when={fileKeywords().length > 0}>
                      {/* Summary */}
                      <section class="mb-7 pb-6 border-b border-border">
                        <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Keyword Summary</h3>
                        <div class="flex gap-6 flex-wrap">
                          <div class="flex flex-col items-center px-6 py-4 bg-bg-panel border border-border rounded-lg min-w-[120px]">
                            <span class="text-2xl font-bold text-accent font-mono">{plainKeywords().length.toLocaleString()}</span>
                            <span class="text-sm text-txt-faint uppercase tracking-wide mt-1">Plain Keywords</span>
                          </div>
                          <div class="flex flex-col items-center px-6 py-4 bg-bg-panel border border-border rounded-lg min-w-[120px]">
                            <span class="text-2xl font-bold text-accent font-mono">{regexKeywords().length.toLocaleString()}</span>
                            <span class="text-sm text-txt-faint uppercase tracking-wide mt-1">Regex Patterns</span>
                          </div>
                          <div class="flex flex-col items-center px-6 py-4 bg-bg-panel border border-border rounded-lg min-w-[120px]">
                            <span class="text-2xl font-bold text-accent font-mono">{fileKeywords().filter(kw => kw.is_case_sensitive).length.toLocaleString()}</span>
                            <span class="text-sm text-txt-faint uppercase tracking-wide mt-1">Case Sensitive</span>
                          </div>
                        </div>
                      </section>
                      
                      {/* Plain Keywords List */}
                      <Show when={plainKeywords().length > 0}>
                        <section class="mb-7 pb-6 border-b border-border">
                          <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">🔤 Plain Keywords ({plainKeywords().length.toLocaleString()})</h3>
                          <div class="bg-bg-panel rounded-lg border border-border overflow-hidden max-h-[500px] overflow-y-auto">
                            <table class="w-full border-collapse text-base">
                              <thead class="sticky top-0 z-[1]">
                                <tr>
                                  <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[50px]">#</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border min-w-[200px]">Keyword</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[80px]">Case</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[150px]">Encodings</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={plainKeywords()}>
                                  {(kw, idx) => (
                                    <tr class="hover:bg-white/[0.03] border-b border-white/5 last:border-b-0">
                                      <td class="px-3 py-2 text-center text-txt-faint font-mono text-xs">{idx() + 1}</td>
                                      <td class="px-3 py-2">
                                        <code class="inline-block bg-bg px-2 py-0.5 rounded font-mono text-sm break-all max-w-[400px]">{kw.value}</code>
                                      </td>
                                      <td class="px-3 py-2 text-center">{kw.is_case_sensitive ? 'Yes' : 'No'}</td>
                                      <td class="px-3 py-2 text-xs text-txt-muted">
                                        {kw.encoding_types.length > 0 ? kw.encoding_types.join(', ') : 'Default'}
                                      </td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </section>
                      </Show>
                      
                      {/* Regex Patterns List */}
                      <Show when={regexKeywords().length > 0}>
                        <section class="mb-7 pb-6 border-b border-border last:border-b-0 last:mb-0">
                          <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">🔣 Regex Patterns ({regexKeywords().length.toLocaleString()})</h3>
                          <div class="bg-bg-panel rounded-lg border border-border overflow-hidden max-h-[500px] overflow-y-auto">
                            <table class="w-full border-collapse text-base">
                              <thead class="sticky top-0 z-[1]">
                                <tr>
                                  <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[50px]">#</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border min-w-[200px]">Pattern</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[80px]">Case</th>
                                  <th class="bg-bg-card px-3 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-txt-faint border-b border-border w-[150px]">Encodings</th>
                                </tr>
                              </thead>
                              <tbody>
                                <For each={regexKeywords()}>
                                  {(kw, idx) => (
                                    <tr class="hover:bg-white/[0.03] border-b border-white/5 last:border-b-0">
                                      <td class="px-3 py-2 text-center text-txt-faint font-mono text-xs">{idx() + 1}</td>
                                      <td class="px-3 py-2">
                                        <code class="inline-block bg-warning-soft text-warning border border-warning/30 px-2 py-0.5 rounded font-mono text-sm break-all max-w-[400px]">{kw.value}</code>
                                      </td>
                                      <td class="px-3 py-2 text-center">{kw.is_case_sensitive ? 'Yes' : 'No'}</td>
                                      <td class="px-3 py-2 text-xs text-txt-muted">
                                        {kw.encoding_types.length > 0 ? kw.encoding_types.join(', ') : 'Default'}
                                      </td>
                                    </tr>
                                  )}
                                </For>
                              </tbody>
                            </table>
                          </div>
                        </section>
                      </Show>
                    </Show>
                    
                    {/* No keywords found fallback */}
                    <Show when={fileKeywords().length === 0}>
                      <section class="mb-7 pb-6 border-b border-border last:border-b-0 last:mb-0">
                        <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Keywords from this File</h3>
                        <div class="flex flex-col items-center justify-center py-10 px-5 text-center gap-3">
                          <span class="text-5xl opacity-50">📋</span>
                          <p class="text-sm text-txt-muted m-0 max-w-[450px]">
                            Individual keywords from this file are not stored in the AXIOM case database.
                          </p>
                          <p class="text-base text-txt-faint m-0 mt-2 max-w-[450px] leading-relaxed">
                            The file contains <strong class="text-accent">{file?.record_count.toLocaleString()}</strong> keywords 
                            that were used during the search, but AXIOM only stores the file reference, 
                            not the individual keyword values.
                          </p>
                          <Show when={file?.file_path}>
                            <p class="text-xs text-txt-faint m-0 mt-3 bg-bg-panel px-4 py-2.5 rounded-md max-w-full break-all">
                              Original file location: <code class="font-mono bg-bg px-1.5 py-0.5 rounded text-xs">{file?.file_path}</code>
                            </p>
                          </Show>
                        </div>
                      </section>
                    </Show>
                  </div>
                );
              })()}
            </Show>

            {/* Artifacts View */}
            <Show when={detailView()?.type === 'artifacts'}>
              <div class="p-6 max-w-[900px]">
                <h2 class="text-xl font-semibold mb-6 text-txt flex items-center gap-2.5">🔎 Artifact Summary</h2>
                
                {/* Search Results from XML */}
                <Show when={caseInfo()?.search_results && caseInfo()!.search_results.length > 0}>
                  <section class="mb-7 pb-6 border-b border-border">
                    <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Search Results ({caseInfo()!.search_results.length} types)</h3>
                    <div class="bg-bg-panel rounded-lg border border-border overflow-hidden">
                      <div class="flex px-4 py-2.5 bg-bg-card border-b border-border text-xs font-semibold uppercase tracking-wide text-txt-faint">
                        <span class="flex-1">Artifact Type</span>
                        <span class="w-[100px] text-right font-mono">Count</span>
                      </div>
                      <For each={caseInfo()?.search_results?.sort((a, b) => b.hit_count - a.hit_count) || []}>
                        {(result) => (
                          <div class="flex px-4 py-2.5 text-base border-b border-white/5 last:border-b-0 hover:bg-white/[0.03]">
                            <span class="flex-1">{result.artifact_type}</span>
                            <span class="w-[100px] text-right font-mono">{result.hit_count.toLocaleString()}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </section>
                </Show>
                
                {/* Category breakdown */}
                <Show when={categories().length > 0}>
                  <section class="mb-7 pb-6 border-b border-border last:border-b-0 last:mb-0">
                    <h3 class="text-sm font-semibold mb-4 text-txt-muted uppercase tracking-wide">Categories ({categories().length})</h3>
                    <div class="grid grid-cols-[repeat(auto-fill,minmax(180px,1fr))] gap-3">
                      <For each={categories()}>
                        {(cat) => (
                          <div class="flex items-center gap-2.5 px-3.5 py-3 bg-bg-panel border border-border rounded-lg hover:bg-bg-hover hover:border-accent transition-colors">
                            <span class="text-xl">{getCategoryIcon(cat.category)}</span>
                            <span class="flex-1 text-base overflow-hidden text-ellipsis whitespace-nowrap">{cat.artifact_type}</span>
                            <span class="text-base font-semibold text-accent">{cat.count.toLocaleString()}</span>
                          </div>
                        )}
                      </For>
                    </div>
                  </section>
                </Show>
              </div>
            </Show>
          </div>
        </Show>
    </div>
  );
};

export default ProcessedDetailPanel;
