/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.attestation;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Result of {@link AttestationVerifier#verify}: one entry per check, in evaluation order.
 *
 * <p>{@link #valid} is {@code true} exactly when at least one check passed and no check failed.
 * {@link Status#SKIP} marks a check whose optional input was not supplied, or whose prerequisite
 * already failed; it never contributes to validity on its own.
 */
public final class VerificationReport {
  /** Outcome of one check. */
  public enum Status {
    PASS,
    FAIL,
    SKIP
  }

  /** One check outcome. */
  public static final class Entry {
    private final String checkId;
    private final Status status;
    private final String detail;

    Entry(String checkId, Status status, String detail) {
      this.checkId = checkId;
      this.status = status;
      this.detail = detail == null ? "" : detail;
    }

    public String checkId() {
      return checkId;
    }

    public Status status() {
      return status;
    }

    public String detail() {
      return detail;
    }
  }

  private final boolean valid;
  private final List<Entry> checks;

  VerificationReport(List<Entry> checks) {
    List<Entry> copy = new ArrayList<Entry>(checks);
    boolean anyPass = false;
    boolean anyFail = false;
    for (Entry entry : copy) {
      anyPass |= entry.status == Status.PASS;
      anyFail |= entry.status == Status.FAIL;
    }
    this.valid = anyPass && !anyFail;
    this.checks = Collections.unmodifiableList(copy);
  }

  public boolean valid() {
    return valid;
  }

  public List<Entry> checks() {
    return checks;
  }

  /** Returns the first entry with {@code checkId}, if any. */
  public Optional<Entry> entry(String checkId) {
    for (Entry entry : checks) {
      if (entry.checkId.equals(checkId)) {
        return Optional.of(entry);
      }
    }
    return Optional.empty();
  }

  /** Returns the status of {@code checkId}, or empty when the check was not recorded. */
  public Optional<Status> status(String checkId) {
    Optional<Entry> entry = entry(checkId);
    return entry.isPresent() ? Optional.of(entry.get().status) : Optional.<Status>empty();
  }

  /** Pretty-printed JSON {@code {"valid": bool, "checks": [{checkId, status, detail}]}}. */
  public String toJson() {
    Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    return gson.toJson(this);
  }

  /** Fixed-width text table: status, check id and detail per line, then the verdict. */
  public String toTable() {
    int width = "CHECK".length();
    for (Entry entry : checks) {
      width = Math.max(width, entry.checkId.length());
    }
    StringBuilder out = new StringBuilder();
    out.append(pad("STATUS", 6)).append("  ").append(pad("CHECK", width)).append("  DETAIL\n");
    for (Entry entry : checks) {
      out.append(pad(entry.status.name(), 6))
          .append("  ")
          .append(pad(entry.checkId, width))
          .append("  ")
          .append(entry.detail)
          .append('\n');
    }
    out.append(valid ? "RESULT: VALID" : "RESULT: INVALID").append('\n');
    return out.toString();
  }

  private static String pad(String value, int width) {
    StringBuilder out = new StringBuilder(value);
    while (out.length() < width) {
      out.append(' ');
    }
    return out.toString();
  }
}
