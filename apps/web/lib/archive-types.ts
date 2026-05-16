export type ArchiveErrorCode =
  | "INVALID_TARBALL_URL"
  | "DOWNLOAD_TIMEOUT"
  | "ARCHIVE_TOO_LARGE"
  | "EXTRACTION_FAILED"
  | "PATH_TRAVERSAL_DETECTED"
  | "SYMLINK_NOT_ALLOWED"
  | "FILE_COUNT_LIMIT_EXCEEDED"
  | "EXTRACTED_SIZE_LIMIT_EXCEEDED"
  | "SINGLE_FILE_LIMIT_EXCEEDED"
  | "CLEANUP_FAILED"
  | "RATE_LIMITED"
  | "NETWORK_ERROR"
  | "UNSUPPORTED_CONTENT_TYPE";

export type TarballExtractResult =
  | {
      ok: true;
      extractedPath: string;
      fileCount: number;
      totalBytes: number;
      cleanup: () => Promise<void>;
      tempId: string;
    }
  | {
      ok: false;
      code: ArchiveErrorCode;
      message: string;
      status?: number;
    };
