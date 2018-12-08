using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	public abstract class AbstractTlsClient : AbstractTlsPeer, TlsClient
	{
		public abstract TlsAuthentication getAuthentication();
		public abstract TlsKeyExchange getKeyExchange();
		public abstract int[] getCipherSuites();
		protected internal TlsCipherFactory cipherFactory;

		protected internal TlsClientContext context;

		protected internal Vector supportedSignatureAlgorithms;
		protected internal int[] namedCurves;
		protected internal short[] clientECPointFormats, serverECPointFormats;

		protected internal int selectedCipherSuite;
		protected internal short selectedCompressionMethod;

		public AbstractTlsClient() : this(new DefaultTlsCipherFactory())
		{
		}

		public AbstractTlsClient(TlsCipherFactory cipherFactory)
		{
			this.cipherFactory = cipherFactory;
		}

		public virtual bool allowUnexpectedServerExtension(int? extensionType, byte[] extensionData)
		{
			switch (extensionType.Value)
			{
			case ExtensionType.elliptic_curves:
				/*
				 * Exception added based on field reports that some servers do send this, although the
				 * Supported Elliptic Curves Extension is clearly intended to be client-only. If
				 * present, we still require that it is a valid EllipticCurveList.
				 */
				TlsECCUtils.readSupportedEllipticCurvesExtension(extensionData);
				return true;

			case ExtensionType.ec_point_formats:
				/*
				 * Exception added based on field reports that some servers send this even when they
				 * didn't negotiate an ECC cipher suite. If present, we still require that it is a valid
				 * ECPointFormatList.
				 */
				TlsECCUtils.readSupportedPointFormatsExtension(extensionData);
				return true;

			default:
				return false;
			}
		}

		public virtual void checkForUnexpectedServerExtension(Hashtable serverExtensions, int? extensionType)
		{
			byte[] extensionData = TlsUtils.getExtensionData(serverExtensions, extensionType);
			if (extensionData != null && !allowUnexpectedServerExtension(extensionType, extensionData))
			{
				throw new TlsFatalAlert(AlertDescription.illegal_parameter);
			}
		}

		public virtual void init(TlsClientContext context)
		{
			this.context = context;
		}

		public virtual TlsSession getSessionToResume()
		{
			return null;
		}

		public virtual ProtocolVersion getClientHelloRecordLayerVersion()
		{
			// "{03,00}"
			// return ProtocolVersion.SSLv3;

			// "the lowest version number supported by the client"
			// return getMinimumVersion();

			// "the value of ClientHello.client_version"
			return getClientVersion();
		}

		public virtual ProtocolVersion getClientVersion()
		{
			return ProtocolVersion.TLSv12;
		}

		public virtual bool isFallback()
		{
			/*
			 * RFC 7507 4. The TLS_FALLBACK_SCSV cipher suite value is meant for use by clients that
			 * repeat a connection attempt with a downgraded protocol (perform a "fallback retry") in
			 * order to work around interoperability problems with legacy servers.
			 */
			return false;
		}

		public virtual Hashtable getClientExtensions()
		{
			Hashtable clientExtensions = null;

			ProtocolVersion clientVersion = context.getClientVersion();

			/*
			 * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior to 1.2.
			 * Clients MUST NOT offer it if they are offering prior versions.
			 */
			if (TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
			{
				// TODO Provide a way for the user to specify the acceptable hash/signature algorithms.

				this.supportedSignatureAlgorithms = TlsUtils.getDefaultSupportedSignatureAlgorithms();

				clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(clientExtensions);

				TlsUtils.addSignatureAlgorithmsExtension(clientExtensions, supportedSignatureAlgorithms);
			}

			if (TlsECCUtils.containsECCCipherSuites(getCipherSuites()))
			{
				/*
				 * RFC 4492 5.1. A client that proposes ECC cipher suites in its ClientHello message
				 * appends these extensions (along with any others), enumerating the curves it supports
				 * and the point formats it can parse. Clients SHOULD send both the Supported Elliptic
				 * Curves Extension and the Supported Point Formats Extension.
				 */
				/*
				 * TODO Could just add all the curves since we support them all, but users may not want
				 * to use unnecessarily large fields. Need configuration options.
				 */
				this.namedCurves = new int[]{NamedCurve.secp256r1, NamedCurve.secp384r1};
				this.clientECPointFormats = new short[]{ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_prime, ECPointFormat.ansiX962_compressed_char2};

				clientExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(clientExtensions);

				TlsECCUtils.addSupportedEllipticCurvesExtension(clientExtensions, namedCurves);
				TlsECCUtils.addSupportedPointFormatsExtension(clientExtensions, clientECPointFormats);
			}

			return clientExtensions;
		}

		public virtual ProtocolVersion getMinimumVersion()
		{
			return ProtocolVersion.TLSv10;
		}

		public virtual void notifyServerVersion(ProtocolVersion serverVersion)
		{
			if (!getMinimumVersion().isEqualOrEarlierVersionOf(serverVersion))
			{
				throw new TlsFatalAlert(AlertDescription.protocol_version);
			}
		}

		public virtual short[] getCompressionMethods()
		{
			return new short[]{CompressionMethod._null};
		}

		public virtual void notifySessionID(byte[] sessionID)
		{
			// Currently ignored
		}

		public virtual void notifySelectedCipherSuite(int selectedCipherSuite)
		{
			this.selectedCipherSuite = selectedCipherSuite;
		}

		public virtual void notifySelectedCompressionMethod(short selectedCompressionMethod)
		{
			this.selectedCompressionMethod = selectedCompressionMethod;
		}

		public virtual void processServerExtensions(Hashtable serverExtensions)
		{
			/*
			 * TlsProtocol implementation validates that any server extensions received correspond to
			 * client extensions sent. By default, we don't send any, and this method is not called.
			 */
			if (serverExtensions != null)
			{
				/*
				 * RFC 5246 7.4.1.4.1. Servers MUST NOT send this extension.
				 */
				checkForUnexpectedServerExtension(serverExtensions, TlsUtils.EXT_signature_algorithms);

				checkForUnexpectedServerExtension(serverExtensions, TlsECCUtils.EXT_elliptic_curves);

				if (TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite))
				{
					this.serverECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(serverExtensions);
				}
				else
				{
					checkForUnexpectedServerExtension(serverExtensions, TlsECCUtils.EXT_ec_point_formats);
				}

				/*
				 * RFC 7685 3. The server MUST NOT echo the extension.
				 */
				checkForUnexpectedServerExtension(serverExtensions, TlsExtensionsUtils.EXT_padding);
			}
		}

		public virtual void processServerSupplementalData(Vector serverSupplementalData)
		{
			if (serverSupplementalData != null)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual Vector getClientSupplementalData()
		{
			return null;
		}

		public override TlsCompression getCompression()
		{
			switch (selectedCompressionMethod)
			{
			case CompressionMethod._null:
				return new TlsNullCompression();

			default:
				/*
				 * Note: internal error here; the TlsProtocol implementation verifies that the
				 * server-selected compression method was in the list of client-offered compression
				 * methods, so if we now can't produce an implementation, we shouldn't have offered it!
				 */
				throw new TlsFatalAlert(AlertDescription.internal_error);
			}
		}

		public override TlsCipher getCipher()
		{
			int encryptionAlgorithm = TlsUtils.getEncryptionAlgorithm(selectedCipherSuite);
			int macAlgorithm = TlsUtils.getMACAlgorithm(selectedCipherSuite);

			return cipherFactory.createCipher(context, encryptionAlgorithm, macAlgorithm);
		}

		public virtual void notifyNewSessionTicket(NewSessionTicket newSessionTicket)
		{
		}
	}

}