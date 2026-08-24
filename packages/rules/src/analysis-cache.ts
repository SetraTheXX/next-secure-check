import type { SourceFile } from "@next-secure-check/core";

export type AnalysisCacheStats = {
  cacheHits: number;
  cacheMisses: number;
};

export class SourceAnalysisCache<TValue> {
  private cache = new WeakMap<SourceFile, TValue>();
  private cacheHits = 0;
  private cacheMisses = 0;

  get(sourceFile: SourceFile, create: () => TValue): TValue {
    const cached = this.cache.get(sourceFile);
    if (cached) {
      this.cacheHits += 1;
      return cached;
    }

    const value = create();
    this.cache.set(sourceFile, value);
    this.cacheMisses += 1;
    return value;
  }

  stats(): AnalysisCacheStats {
    return {
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses
    };
  }

  clear(): void {
    this.cache = new WeakMap<SourceFile, TValue>();
    this.cacheHits = 0;
    this.cacheMisses = 0;
  }
}
