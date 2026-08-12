package dev.mistial.tools.openfips201.common;

import apdu4j.core.BIBO;

/** Opens independent card connections for workflows with explicit security-domain boundaries. */
@FunctionalInterface
public interface CardConnectionFactory {
  BIBO open() throws Exception;
}
