"use client";

import Editor, { loader } from "@monaco-editor/react";

loader.config({
  paths: { vs: "https://cdn.jsdelivr.net/npm/monaco-editor@0.52.2/min/vs" },
});

interface CodeEditorProps {
  value: string;
  language: string;
  onChange: (value: string) => void;
}

export default function CodeEditor({ value, language, onChange }: CodeEditorProps) {
  const monacoLanguage = language === "python" ? "python" : "javascript";

  return (
    <div className="h-96 overflow-hidden rounded-lg border border-neutral-700">
      <Editor
        height="100%"
        language={monacoLanguage}
        theme="vs-dark"
        value={value}
        onChange={(newValue) => onChange(newValue ?? "")}
        options={{
          minimap: { enabled: false },
          fontSize: 14,
          scrollBeyondLastLine: false,
        }}
      />
    </div>
  );
}