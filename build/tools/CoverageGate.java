import java.io.File;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** Fails the build when the bundle-level JaCoCo line ratio drops below its ratchet. */
public final class CoverageGate {
  private CoverageGate() {}

  public static void main(String[] arguments) throws Exception {
    if (arguments.length != 2) {
      throw new IllegalArgumentException("usage: CoverageGate <jacoco.xml> <minimum-ratio>");
    }

    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
    factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
    Element report =
        factory.newDocumentBuilder().parse(new File(arguments[0])).getDocumentElement();
    Element lineCounter = findDirectLineCounter(report);
    long missed = Long.parseLong(lineCounter.getAttribute("missed"));
    long covered = Long.parseLong(lineCounter.getAttribute("covered"));
    double ratio = covered / (double) (covered + missed);
    double minimum = Double.parseDouble(arguments[1]);

    System.out.printf("Line coverage: %.2f%% (minimum %.2f%%)%n", ratio * 100, minimum * 100);
    if (ratio < minimum) {
      throw new IllegalStateException("line coverage is below the configured minimum");
    }
  }

  private static Element findDirectLineCounter(Element report) {
    NodeList children = report.getChildNodes();
    for (int index = 0; index < children.getLength(); index++) {
      Node child = children.item(index);
      if (child instanceof Element) {
        Element element = (Element) child;
        if ("counter".equals(element.getTagName()) && "LINE".equals(element.getAttribute("type"))) {
          return element;
        }
      }
    }
    throw new IllegalStateException("JaCoCo report has no bundle line counter");
  }
}
