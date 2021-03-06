package uk.gov.ida.notification.saml;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;
import uk.gov.ida.notification.exceptions.saml.SamlParsingException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Objects;

import static javax.xml.XMLConstants.FEATURE_SECURE_PROCESSING;

/**
 * Due to security requirements, {@link javax.xml.parsers.DocumentBuilder} and
 * {@link javax.xml.parsers.DocumentBuilderFactory} should *only* be used via
 * the utility methods in this class.  For more information on the vulnerabilities
 * identified, see the tests.
 */
@SuppressWarnings("unchecked")
public class SamlParser {
    private final DocumentBuilder documentBuilder;
    private final UnmarshallerFactory unmarshallerFactory;

    public SamlParser() throws ParserConfigurationException {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature(FEATURE_SECURE_PROCESSING, true);
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setNamespaceAware(true);
        documentBuilder = dbf.newDocumentBuilder();
        unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
    }

    public <T extends XMLObject> T parseSamlString(String xmlString) {
        ByteArrayInputStream inputStream = new ByteArrayInputStream(xmlString.getBytes());

        try {
            Document document = documentBuilder.parse(inputStream);
            Element element = document.getDocumentElement();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return (T) Objects.requireNonNull(
                unmarshaller, String.format("No unmarshaller for element <%s>", element.getTagName())
            ).unmarshall(element);
        } catch (NullPointerException | SAXException | IOException | UnmarshallingException e) {
            throw new SamlParsingException(e);
        }
    }
}
