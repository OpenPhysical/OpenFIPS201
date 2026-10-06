/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201;

import dev.mistial.tools.openfips201.common.HexUtil;
import dev.mistial.tools.openfips201.issuance.ProductionContext;
import dev.mistial.tools.openfips201.issuance.StationKeys;
import dev.mistial.tools.openfips201.producer.ProducerSetupService;
import dev.mistial.tools.openfips201.producer.StationGuard;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Production-station handoff keys: created at production, imported at the root. */
@Command(
    name = "station",
    mixinStandardHelpOptions = true,
    description = "Create (production) and import (root) station handoff keys.",
    subcommands = {StationCommand.Init.class, StationCommand.Import.class})
final class StationCommand implements Callable<Integer> {
  @Override
  public Integer call() {
    CommandLine.usage(this, System.err);
    return 2;
  }

  @Command(
      name = "init",
      mixinStandardHelpOptions = true,
      description =
          "Production station: create the handoff ECDH key on the production token and write its"
              + " public key (station.pem) for 'station import' at the root.")
  static final class Init implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--out", required = true, description = "New station.pem file.")
    Path out;

    @Override
    public Integer call() throws Exception {
      byte[] point;
      try (ProductionContext context = ProductionContext.load(producer)) {
        context.requireProductionClean(producer);
        point = context.stationPoint();
      }
      StationKeys.writeStationPem(out, point);
      System.out.println("Station key written: " + out);
      System.out.println("Station SKI: " + HexUtil.format(StationKeys.ski(point)));
      return 0;
    }
  }

  @Command(
      name = "import",
      mixinStandardHelpOptions = true,
      description = "Root station: store a production station's station.pem under a name.")
  static final class Import implements Callable<Integer> {
    @Option(names = "--producer", required = true)
    String producer;

    @Option(names = "--name", required = true, description = "Station name.")
    String name;

    @Option(names = "--pub", required = true, description = "station.pem.")
    Path pub;

    @Override
    public Integer call() throws Exception {
      StationGuard.requireStation(producer, ProducerSetupService.STATION_ROOT);
      Path stored = StationKeys.importStation(producer, name, pub);
      System.out.println(
          "Station "
              + name
              + " imported ("
              + HexUtil.format(StationKeys.ski(StationKeys.readPoint(stored)))
              + ").");
      return 0;
    }
  }
}
