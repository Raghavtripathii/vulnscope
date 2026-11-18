export interface Issue {
  index: number;
  line_number: number | null;
  vulnerability_class: string;
  label: string;
  cwe: string | null;
  owasp: string | null;
  severity: string;
  code_snippet: string | null;
  detectors: string[];
}

export interface Explanation {
  vulnerability_type: string;
  exploit_scenario: string;
  fixed_code_example: string;
  owasp_mapping: string | null;
  source: "llm" | "static";
  fix_rescan: "clean" | "not_checked";
}

export interface ExerciseSummary {
  id: string;
  vulnerability_class: string;
  label: string;
  language: "python" | "javascript";
  title: string;
  completed: boolean;
}

export interface ExerciseDetail extends ExerciseSummary {
  scenario: string;
  vulnerable_code: string;
  hint: string;
}

export interface RemainingIssue {
  line_number: number | null;
  vulnerability_class: string;
  label: string;
}

export interface AttemptResponse {
  passed: boolean;
  remaining: RemainingIssue[];
  detectors: Record<string, string>;
  reference_fix: string | null;
}

export interface ExerciseProgress {
  exercise_id: string;
  title: string;
  vulnerability_class: string;
  attempts: number;
  completed: boolean;
  last_attempt_at: string | null;
}

export interface ClassProgress {
  vulnerability_class: string;
  label: string;
  total: number;
  completed: number;
}

export interface ProgressResponse {
  exercises_total: number;
  exercises_completed: number;
  by_class: ClassProgress[];
  exercises: ExerciseProgress[];
}

export interface MyScan {
  scan_id: number;
  language: string;
  filename: string | null;
  created_at: string;
  issue_count: number;
  issues_by_class: Record<string, number>;
}

export interface RepeatedMistake {
  vulnerability_class: string;
  label: string;
  scans_affected: number;
  issues_total: number;
  last_seen: string | null;
}

export interface MyStats {
  scans_count: number;
  issues_total: number;
  issues_by_class: Record<string, number>;
  repeated_mistakes: RepeatedMistake[];
}

export interface ClassStat {
  vulnerability_class: string;
  label: string;
  issues_total: number;
  students_affected: number;
  students_repeating: number;
  share_of_students: number;
}

export interface TeacherStats {
  students_count: number;
  scans_count: number;
  issues_total: number;
  classes: ClassStat[];
}