package sample.spring.security;

import io.spiffe.bundle.x509bundle.X509Bundle;
import io.spiffe.exception.BundleNotFoundException;
import io.spiffe.exception.SocketEndpointAddressException;
import io.spiffe.exception.X509SourceException;
import io.spiffe.provider.SpiffeKeyManager;
import io.spiffe.workloadapi.DefaultX509Source;
import io.spiffe.workloadapi.X509Source;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

/**
 * The X509SourceSingletonWrapper wraps an internal X509Source as singleton.
 * <p>
 * The internal X509Source instance can be initialized using:
 * <pre>
 * {@code
 * X509Source myX509SourceSingleton = X509SourceSingletonWrapper.getInstance().getX509Source();
 * }
 * </>
 * or
 * <pre>
 * {@code
 * X509Source myX509SourceSingleton = X509SourceSingletonWrapper.getInstance(x509SourceOptions).getX509Source();
 * }
 * </pre>
 * <p>
 * Additionally, the class provides convenient access to an SSLContext initialized with the X509Source instance as KeyManager using.
 *
 * <pre>
 * {@code
 * SSLContext sslContext = X509SourceSingletonWrapper.getInstance().getSslContextInstance();
 * }
 * </>
 * or
 * <pre>
 * {@code
 * SSLContext sslContext = X509SourceSingletonWrapper.getInstance(x509SourceOptions).getSslContextInstance();
 * }
 * </pre>
 * <p>
 * Note: If their are multiple SVIDs available via the workload API, then the class will select one following the defaults implemented as part of the 'java-spiffe' provided libs.
 * <p>
 * Required dependencies see pom.xml under "SVIDs/SPIFFE/X509SourceSingletonWrapper".
 */
public class X509SourceSingletonWrapper {

	private final static Logger LOGGER = LoggerFactory.getLogger(X509SourceSingletonWrapper.class);

	private static final String DEFAULT_SPIFFE_ENDPOINT_SOCKET = "unix:///tmp/spire-agent/public/api.sock";

	private static X509Source x509Source;

	private static X509SourceSingletonWrapper x509SourceSingletonWrapper = new X509SourceSingletonWrapper();

	private X509SourceSingletonWrapper() {
		//hide constructor
	}

	/**
	 * Returns a singleton instance of the X509SourceSingletonWrapper which initialized its internal x509Source with the
	 * spiffe socket endpoint set by the "SPIFFE_ENDPOINT_SOCKET" environment variable, or if the environment variable
	 * is not set, it uses 'unix:///tmp/spire-agent/public/api.sock'. {@code  DefaultX509Source.newSource()}.
	 *
	 * @return Singleton instance of the X509SourceSingletonWrapper
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 */

	public static X509SourceSingletonWrapper getInstance()
			throws GeneralSecurityException, IOException, SocketEndpointAddressException, X509SourceException {

		if (x509Source != null) {
			return x509SourceSingletonWrapper;
		}
		synchronized (X509SourceSingletonWrapper.class) {
			if (x509Source != null) {
				return x509SourceSingletonWrapper;
			}

			String spiffeEndpointSocket = DEFAULT_SPIFFE_ENDPOINT_SOCKET;
			if (System.getenv("SPIFFE_ENDPOINT_SOCKET") != null) {
				spiffeEndpointSocket = System.getenv("SPIFFE_ENDPOINT_SOCKET");
				LOGGER.debug(
						"spiffeEndpointSocket is set based on the SPIFFE_ENDPOINT_SOCKET environment variable.");
			}
			LOGGER.debug("spiffeEndpointSocket: {}", spiffeEndpointSocket);

			DefaultX509Source.X509SourceOptions x509SourceOptions = DefaultX509Source.X509SourceOptions.builder()
					.spiffeSocketPath(spiffeEndpointSocket).build();

			x509Source = DefaultX509Source.newSource(x509SourceOptions);
			return x509SourceSingletonWrapper;
		}
	}

	/**
	 * @return Returns true, if an Svid is available to the internal x509Source.
	 */
	public static boolean isSvidAvailable() {
		try {
			if (x509Source != null && x509Source.getX509Svid() != null) {
				return true;
			}
		} catch (Exception e) {
			LOGGER.warn("No Svid available (No Svid has been retrieved via Workload API). Exception: {}",
					e.getMessage());
		}
		LOGGER.debug("Svid available (Svid has been successfully retrieved via Workload API).");
		return false;
	}

	/**
	 * Returns a singleton instance of the wrapped X509Source.
	 *
	 * @return Singleton instance of an X509Source
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 */
	public X509Source getX509Source() {
		return x509Source;
	}

	/**
	 * Returns the chain of X.509 certificates used by the wrapped X509Source instance.
	 *
	 * @return the chain of X.509 certificates used by the X509SourceSingletonWrapper
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 */
	public X509Certificate[] getCertificateChainArray()
			throws IOException, SocketEndpointAddressException, X509SourceException, GeneralSecurityException {

		return x509Source.getX509Svid().getChainArray();
	}

	/**
	 * Returns the leaf X.509 certificate used by the wrapped X509Source instance.
	 *
	 * @return the leaf X.509 certificate used by the X509SourceSingletonWrapper
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 */
	public X509Certificate getLeaf()
			throws IOException, SocketEndpointAddressException, X509SourceException, GeneralSecurityException {
		return x509Source.getX509Svid().getLeaf();
	}

	/**
	 * Returns the X.509 bundle associated to the trust domain used by the wrapped X509Source instance.
	 *
	 * @return the trust domain used by the X509SourceSingletonWrapper
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 * @throws BundleNotFoundException
	 * 		if no X.509 bundle can be found
	 */
	public X509Bundle getBundleForTrustDomain()
			throws IOException, SocketEndpointAddressException, X509SourceException, BundleNotFoundException,
			GeneralSecurityException {

		return x509Source.getBundleForTrustDomain(
				x509Source.getX509Svid().getSpiffeId().getTrustDomain());
	}

	/**
	 * Returns an SslContext that is initialized using the wrapped X509Source instance as follows:
	 * <pre>
	 * {@code
	 * SSLContext sslContext = SSLContext.getInstance("TLS");
	 * sslContext.init(new KeyManager[]{new SpiffeKeyManager(x509Source)}, null, null);
	 * }
	 * </pre>
	 * <p>
	 *
	 * @return SslContext initalized as described above.
	 * @throws GeneralSecurityException
	 * @throws IOException
	 * @throws SocketEndpointAddressException
	 * 		if the address to the Workload API is not valid
	 * @throws X509SourceException
	 * 		if the source could not be initialized
	 */
	public SSLContext getSslContextInstance()
			throws GeneralSecurityException, IOException, SocketEndpointAddressException, X509SourceException {

		SSLContext sslContext = SSLContext.getInstance("TLS");
		sslContext.init(new KeyManager[] { new SpiffeKeyManager(x509Source) }, null, null);
		return sslContext;
	}

}