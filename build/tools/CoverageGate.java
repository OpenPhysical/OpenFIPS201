import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Fails the build when a JaCoCo XML report drops below any of its ratchets.
 *
 * <p>Usage: {@code CoverageGate <jacoco.xml> <rule>...}. A rule is {@code COUNTER=minimum} for the
 * report-level counter, or {@code Class:COUNTER=minimum} for one class (its nested classes
 * included). COUNTER is a JaCoCo counter type such as LINE, BRANCH or INSTRUCTION; minimum is a
 * ratio in [0, 1]. Every rule is evaluated and printed before the gate fails.
 */
public final class CoverageGate {
  private CoverageGate() {}

  public static void main(String[] arguments) throws Exception {
    if (arguments.length < 2) {
      throw new IllegalArgumentException(
          "usage: CoverageGate <jacoco.xml> [Class:]COUNTER=minimum...");
    }

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    Element report =
        factory.newDocumentBuilder().parse(new File(arguments[0])).getDocumentElement();

    System.out.printf(
        "%s: line %s, branch %s, instruction %s%n",
        report.getAttribute("name"),
        percent(directCounter(report, "LINE")),
        percent(directCounter(report, "BRANCH")),
        percent(directCounter(report, "INSTRUCTION")));

    List<String> failures = new ArrayList<String>();
    for (int index = 1; index < arguments.length; index++) {
      String rule = arguments[index];
      int equals = rule.indexOf('=');
      int colon = rule.indexOf(':');
      if (equals < 0 || colon > equals) {
        throw new IllegalArgumentException("malformed rule: " + rule);
      }
      String scope = colon < 0 ? null : rule.substring(0, colon);
      String type = rule.substring(colon + 1, equals);
      double minimum = Double.parseDouble(rule.substring(equals + 1));
      long[] counter =
          scope == null ? directCounter(report, type) : classCounter(report, scope, type);
      if (counter == null) {
        throw new IllegalStateException("JaCoCo report has no " + type + " counter for " + rule);
      }
      double ratio = ratio(counter);
      boolean passed = ratio >= minimum;
      System.out.printf(
          "  %-48s %7.2f%% (minimum %.2f%%) %s%n",
          (scope == null ? "bundle" : scope) + " " + type,
          ratio * 100,
          minimum * 100,
          passed ? "ok" : "BELOW");
      if (!passed) failures.add(rule);
    }
    if (!failures.isEmpty()) {
      throw new IllegalStateException("coverage is below the configured minimum: " + failures);
    }
  }

  private static String percent(long[] counter) {
    return counter == null ? "n/a" : String.format("%.2f%%", ratio(counter) * 100);
  }

  private static double ratio(long[] counter) {
    long total = counter[0] + counter[1];
    return total == 0 ? 1.0 : counter[1] / (double) total;
  }

  /** Returns {missed, covered} of the counter that is a direct child of {@code parent}. */
  private static long[] directCounter(Element parent, String type) {
    NodeList children = parent.getChildNodes();
    for (int index = 0; index < children.getLength(); index++) {
      Node child = children.item(index);
      if (child instanceof Element) {
        Element element = (Element) child;
        if ("counter".equals(element.getTagName()) && type.equals(element.getAttribute("type"))) {
          return new long[] {
            Long.parseLong(element.getAttribute("missed")),
            Long.parseLong(element.getAttribute("covered"))
          };
        }
      }
    }
    return null;
  }

  /** Sums {@code type} over the classes named {@code simpleName} or nested in it. */
  private static long[] classCounter(Element report, String simpleName, String type) {
    NodeList classes = report.getElementsByTagName("class");
    long[] sum = null;
    for (int index = 0; index < classes.getLength(); index++) {
      Element element = (Element) classes.item(index);
      String name = element.getAttribute("name");
      String simple = name.substring(name.lastIndexOf('/') + 1);
      if (!simple.equals(simpleName) && !simple.startsWith(simpleName + "$")) continue;
      long[] counter = directCounter(element, type);
      if (counter == null) continue;
      if (sum == null) sum = new long[2];
      sum[0] += counter[0];
      sum[1] += counter[1];
    }
    return sum;
  }
}
