import { useEffect, useMemo, useState } from "react";
import { describeError } from "./api";

interface Loaded<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

interface Result<T> {
  request: object | null; // which request this result belongs to
  data: T | null;
  error: string | null;
}

/**
 * Runs `load` when the page opens, and again when `load` changes (wrap it in
 * useCallback) or when reload() is called.
 *
 * An answer that arrives after a newer request started is thrown away, so a
 * slow old reply can never overwrite newer data on screen. The old data stays
 * visible while new data loads.
 */
export function useLoad<T>(load: () => Promise<T>): Loaded<T> {
  const [round, setRound] = useState(0);
  const request = useMemo(() => ({ load, round }), [load, round]);
  const [result, setResult] = useState<Result<T>>({ request: null, data: null, error: null });

  useEffect(() => {
    let current = true;
    request
      .load()
      .then((data) => {
        if (current) setResult({ request, data, error: null });
      })
      .catch((problem: unknown) => {
        if (current) setResult((old) => ({ request, data: old.data, error: describeError(problem) }));
      });
    return () => {
      current = false;
    };
  }, [request]);

  return {
    data: result.data,
    error: result.error,
    loading: result.request !== request,
    reload: () => setRound((n) => n + 1),
  };
}
