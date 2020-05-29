package com.sap.cloud.security.cas.spring;

/**
 * TODO: use WebClient instead of RestTemplate
 */
/**public class SpringADCService implements ADCService {
    private static final Logger LOGGER = LoggerFactory.getLogger(SpringADCService.class);

    private final RestOperations restOperations;

    public SpringADCService() {
       this(null);
    }

    public SpringADCService(RestOperations restOperations) {
        if (Objects.nonNull(restOperations)) {
            this.restOperations = restOperations;
        } else {
            this.restOperations = new RestTemplate();
        }
    }

    @Override
    public ADCServiceResponse isUserAuthorized(URI adcUri, ADCServiceRequest request) {
        HttpEntity<?> httpRequest = new HttpEntity<>(request);
        try {
            return restOperations.postForObject(adcUri, httpRequest, ADCServiceResponse.class);
        } catch (RestClientException e) {
            LOGGER.error("Error accessing ADC service {}: {}.", adcUri, e.getCause(), e);
            return new ADCServiceResponse();
        }
    }

    @Override
    public boolean ping(URI adcBaseUri) {
        URI adcHealthEndpoint = expandPath(adcBaseUri, "/health");
        try {
            boolean isHealthy = restOperations.getForEntity(adcHealthEndpoint, Object.class).getStatusCode() == HttpStatus.OK;
            LOGGER.info("Ping ADC service {}: {}", adcHealthEndpoint, isHealthy);
            return isHealthy;
        } catch (RestClientException e) {
            LOGGER.warn("Ping ADC service {}: {}.", adcHealthEndpoint, e.getMessage());
            return false;
        }
    }

    // TODO replace with UriUtil.expandPath
    public static URI expandPath(URI baseUri, String pathToAppend) {
        try {
            String newPath = baseUri.getPath() + pathToAppend;
            return new URI(baseUri.getScheme(), baseUri.getUserInfo(), baseUri.getHost(), baseUri.getPort(),
                    replaceDoubleSlashes(newPath), baseUri.getQuery(), baseUri.getFragment());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String replaceDoubleSlashes(String newPath) {
        return newPath.replaceAll("//", "/");
    }
}*/
