/******************************************************************************
 * MIT License
 *
 * Project: OpenFIPS201
 * Copyright: (c) 2026 OpenPhysical
 ******************************************************************************/

package dev.mistial.tools.openfips201.gp;

import apdu4j.core.BIBO;
import dev.mistial.tools.openfips201.common.CardTarget;
import dev.mistial.tools.openfips201.common.HexUtil;
import java.util.LinkedHashMap;
import java.util.Map;
import pro.javacard.gp.CPLC;
import pro.javacard.gp.GPData;

public final class CardIdentityService {
  public Result read(CardTarget target) throws Exception {
    try (BIBO bibo = target.openBibo()) {
      byte[] cplcBytes = GPData.fetchCPLC(bibo);
      CPLC cplc = CPLC.fromBytes(cplcBytes);
      Map<String, String> fields = new LinkedHashMap<String, String>();
      for (CPLC.Field field : CPLC.Field.values()) {
        fields.put(field.name(), HexUtil.format(cplc.get(field)));
      }
      return new Result(HexUtil.format(cplcBytes), fields);
    }
  }

  public static final class Result {
    public final String cplc;
    public final Map<String, String> cplcFields;

    Result(String cplc, Map<String, String> cplcFields) {
      this.cplc = cplc;
      this.cplcFields = cplcFields;
    }
  }
}
