package uk.gov.ida.notification.resources;

import io.dropwizard.views.View;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.x509.X509Credential;
import uk.gov.ida.notification.EidasResponseGenerator;
import uk.gov.ida.notification.SamlFormViewBuilder;
import uk.gov.ida.notification.exceptions.hubresponse.HubResponseException;
import uk.gov.ida.notification.saml.ResponseAssertionEncrypter;
import uk.gov.ida.notification.saml.SamlFormMessageType;
import uk.gov.ida.notification.saml.metadata.Metadata;
import uk.gov.ida.notification.saml.translation.HubResponseContainer;
import uk.gov.ida.notification.saml.validation.HubResponseValidator;
import uk.gov.ida.notification.saml.validation.components.ResponseAttributesValidator;
import uk.gov.ida.saml.core.validators.DestinationValidator;
import uk.gov.ida.saml.core.validators.assertion.AssertionAttributeStatementValidator;
import uk.gov.ida.saml.core.validators.assertion.AuthnStatementAssertionValidator;
import uk.gov.ida.saml.core.validators.assertion.DuplicateAssertionValidator;
import uk.gov.ida.saml.core.validators.assertion.IPAddressValidator;
import uk.gov.ida.saml.core.validators.assertion.IdentityProviderAssertionValidator;
import uk.gov.ida.saml.core.validators.assertion.MatchingDatasetAssertionValidator;
import uk.gov.ida.saml.core.validators.subject.AssertionSubjectValidator;
import uk.gov.ida.saml.core.validators.subjectconfirmation.AssertionSubjectConfirmationValidator;
import uk.gov.ida.saml.hub.transformers.inbound.SamlStatusToIdpIdaStatusMappingsFactory;
import uk.gov.ida.saml.hub.validators.response.idp.IdpResponseValidator;
import uk.gov.ida.saml.hub.validators.response.idp.components.EncryptedResponseFromIdpValidator;
import uk.gov.ida.saml.hub.validators.response.idp.components.ResponseAssertionsFromIdpValidator;
import uk.gov.ida.saml.security.AssertionDecrypter;
import uk.gov.ida.saml.security.SamlAssertionsSignatureValidator;
import uk.gov.ida.saml.security.SamlMessageSignatureValidator;
import uk.gov.ida.saml.security.validators.issuer.IssuerValidator;
import uk.gov.ida.saml.security.validators.signature.SamlResponseSignatureValidator;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import java.net.URI;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.logging.Logger;

@Path("/SAML2/SSO/Response")
public class HubResponseResource {
    private static final Logger LOG = Logger.getLogger(HubResponseResource.class.getName());

    private final EidasResponseGenerator eidasResponseGenerator;
    private final SamlFormViewBuilder samlFormViewBuilder;
    private final AssertionDecrypter assertionDecrypter;
    private final String connectorNodeUrl;
    private final String connectorEntityId;
    private final Metadata connectorMetadata;
    private URI proxyNodeResponseUrl;
    private final SamlMessageSignatureValidator hubResponseMessageSignatureValidator;
    private String proxyNodeEntityId;

    public HubResponseResource(
        EidasResponseGenerator eidasResponseGenerator,
        SamlFormViewBuilder samlFormViewBuilder,
        AssertionDecrypter assertionDecrypter,
        String connectorNodeUrl,
        String connectorEntityId,
        Metadata connectorMetadata,
        URI proxyNodeResponseUrl,
        String proxyNodeEntityId,
        SamlMessageSignatureValidator hubResponseMessageSignatureValidator) {
        this.assertionDecrypter = assertionDecrypter;
        this.connectorNodeUrl = connectorNodeUrl;
        this.eidasResponseGenerator = eidasResponseGenerator;
        this.samlFormViewBuilder = samlFormViewBuilder;
        this.connectorEntityId = connectorEntityId;
        this.connectorMetadata = connectorMetadata;
        this.proxyNodeResponseUrl = proxyNodeResponseUrl;
        this.proxyNodeEntityId = proxyNodeEntityId;
        this.hubResponseMessageSignatureValidator = hubResponseMessageSignatureValidator;
    }

    @POST
    @Path("/POST")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public View hubResponse(
            @FormParam(SamlFormMessageType.SAML_RESPONSE) Response encryptedHubResponse,
            @FormParam("RelayState") String relayState) {
        try {
            HubResponseValidator validator = createHubResponseValidator();
            validator.validate(encryptedHubResponse);

            HubResponseContainer hubResponseContainer = HubResponseContainer.from(
                validator.getValidatedResponse(),
                validator.getValidatedAssertions()
            );
            logHubResponse(hubResponseContainer);

            ResponseAssertionEncrypter assertionEncrypter = createAssertionEncrypter();

            Response securedEidasResponse = eidasResponseGenerator.generate(hubResponseContainer, assertionEncrypter);
            logEidasResponse(securedEidasResponse);

            return samlFormViewBuilder.buildResponse(connectorNodeUrl, securedEidasResponse, "Post eIDAS Response SAML to Connector Node", relayState);
        } catch (Throwable e) {
            throw new HubResponseException(e, encryptedHubResponse);
        }
    }

    private HubResponseValidator createHubResponseValidator() {
        SamlAssertionsSignatureValidator samlAssertionsSignatureValidator = new SamlAssertionsSignatureValidator(hubResponseMessageSignatureValidator);
        SamlResponseSignatureValidator samlResponseSignatureValidator = new SamlResponseSignatureValidator(hubResponseMessageSignatureValidator);

        SamlStatusToIdpIdaStatusMappingsFactory statusMappings = new SamlStatusToIdpIdaStatusMappingsFactory();
        EncryptedResponseFromIdpValidator responseFromIdpValidator = new EncryptedResponseFromIdpValidator(statusMappings);
        DestinationValidator destinationValidator = new DestinationValidator(proxyNodeResponseUrl, proxyNodeResponseUrl.getPath());
        IssuerValidator issuerValidator = new IssuerValidator();
        AssertionSubjectValidator subjectValidator = new AssertionSubjectValidator();
        AssertionAttributeStatementValidator assertionAttributeStatementValidator = new AssertionAttributeStatementValidator();
        AssertionSubjectConfirmationValidator subjectConfirmationValidator = new AssertionSubjectConfirmationValidator();
        IdentityProviderAssertionValidator assertionValidator = new IdentityProviderAssertionValidator(
            issuerValidator,
            subjectValidator,
            assertionAttributeStatementValidator,
            subjectConfirmationValidator
        );
        ConcurrentMap<String, DateTime> duplicateIds = new ConcurrentHashMap<>();
        DuplicateAssertionValidator duplicateAssertionValidator = new DuplicateAssertionValidator(duplicateIds);
        MatchingDatasetAssertionValidator matchingDatasetAssertionValidator = new MatchingDatasetAssertionValidator(duplicateAssertionValidator);
        AuthnStatementAssertionValidator authnStatementAssertionValidator = new AuthnStatementAssertionValidator(duplicateAssertionValidator);
        IPAddressValidator ipAddressValidator = new IPAddressValidator();
        ResponseAssertionsFromIdpValidator responseAssertionsFromIdpValidator = new ResponseAssertionsFromIdpValidator(
            assertionValidator,
            matchingDatasetAssertionValidator,
            authnStatementAssertionValidator,
            ipAddressValidator,
            proxyNodeEntityId
        );

        IdpResponseValidator idpResponseValidator = new IdpResponseValidator(
            samlResponseSignatureValidator,
            assertionDecrypter,
            samlAssertionsSignatureValidator,
            responseFromIdpValidator,
            destinationValidator,
            responseAssertionsFromIdpValidator
        );

        ResponseAttributesValidator responseAttributesValidator = new ResponseAttributesValidator();
        return new HubResponseValidator(idpResponseValidator, responseAttributesValidator);
    }

    private ResponseAssertionEncrypter createAssertionEncrypter() {
        X509Credential encryptionCredential = (X509Credential) connectorMetadata.getCredential(UsageType.ENCRYPTION, connectorEntityId, SPSSODescriptor.DEFAULT_ELEMENT_NAME);
        return new ResponseAssertionEncrypter(encryptionCredential);
    }

    private void logHubResponse(HubResponseContainer hubResponseContainer) {
        LOG.info("[Hub Response] ID: " + hubResponseContainer.getHubResponse().getResponseId());
        LOG.info("[Hub Response] In response to: " + hubResponseContainer.getHubResponse().getInResponseTo());
        LOG.info("[Hub Response] Provided level of assurance: " + hubResponseContainer.getAuthnAssertion().getProvidedLoa());
    }

    private void logEidasResponse(Response eidasResponse) {
        LOG.info("[eIDAS Response] ID: " + eidasResponse.getID());
        LOG.info("[eIDAS Response] In response to: " + eidasResponse.getInResponseTo());
    }

}
