using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using Arrays = org.bouncycastle.util.Arrays;

	public abstract class AbstractTlsServer : AbstractTlsPeer, TlsServer
	{
		public abstract TlsKeyExchange getKeyExchange();
		public abstract TlsCredentials getCredentials();
		protected internal TlsCipherFactory cipherFactory;

		protected internal TlsServerContext context;

		protected internal ProtocolVersion clientVersion;
		protected internal int[] offeredCipherSuites;
		protected internal short[] offeredCompressionMethods;
		protected internal Hashtable clientExtensions;

		protected internal bool encryptThenMACOffered;
		protected internal short maxFragmentLengthOffered;
		protected internal bool truncatedHMacOffered;
		protected internal Vector supportedSignatureAlgorithms;
		protected internal bool eccCipherSuitesOffered;
		protected internal int[] namedCurves;
		protected internal short[] clientECPointFormats, serverECPointFormats;

		protected internal ProtocolVersion serverVersion;
		protected internal int selectedCipherSuite;
		protected internal short selectedCompressionMethod;
		protected internal Hashtable serverExtensions;

		public AbstractTlsServer() : this(new DefaultTlsCipherFactory())
		{
		}

		public AbstractTlsServer(TlsCipherFactory cipherFactory)
		{
			this.cipherFactory = cipherFactory;
		}

		public virtual bool allowEncryptThenMAC()
		{
			return true;
		}

		public virtual bool allowTruncatedHMac()
		{
			return false;
		}

		public virtual Hashtable checkServerExtensions()
		{
			return this.serverExtensions = TlsExtensionsUtils.ensureExtensionsInitialised(this.serverExtensions);
		}

		public abstract int[] getCipherSuites();

		public virtual short[] getCompressionMethods()
		{
			return new short[]{CompressionMethod._null};
		}

		public virtual ProtocolVersion getMaximumVersion()
		{
			return ProtocolVersion.TLSv11;
		}

		public virtual ProtocolVersion getMinimumVersion()
		{
			return ProtocolVersion.TLSv10;
		}

		public virtual bool supportsClientECCCapabilities(int[] namedCurves, short[] ecPointFormats)
		{
			// NOTE: BC supports all the current set of point formats so we don't check them here

			if (namedCurves == null)
			{
				/*
				 * RFC 4492 4. A client that proposes ECC cipher suites may choose not to include these
				 * extensions. In this case, the server is free to choose any one of the elliptic curves
				 * or point formats [...].
				 */
				return TlsECCUtils.hasAnySupportedNamedCurves();
			}

			for (int i = 0; i < namedCurves.Length; ++i)
			{
				int namedCurve = namedCurves[i];
				if (NamedCurve.isValid(namedCurve) && (!NamedCurve.refersToASpecificNamedCurve(namedCurve) || TlsECCUtils.isSupportedNamedCurve(namedCurve)))
				{
					return true;
				}
			}

			return false;
		}

		public virtual void init(TlsServerContext context)
		{
			this.context = context;
		}

		public virtual void notifyClientVersion(ProtocolVersion clientVersion)
		{
			this.clientVersion = clientVersion;
		}

		public virtual void notifyFallback(bool isFallback)
		{
			/*
			 * RFC 7507 3. If TLS_FALLBACK_SCSV appears in ClientHello.cipher_suites and the highest
			 * protocol version supported by the server is higher than the version indicated in
			 * ClientHello.client_version, the server MUST respond with a fatal inappropriate_fallback
			 * alert [..].
			 */
			if (isFallback && getMaximumVersion().isLaterVersionOf(clientVersion))
			{
				throw new TlsFatalAlert(AlertDescription.inappropriate_fallback);
			}
		}

		public virtual void notifyOfferedCipherSuites(int[] offeredCipherSuites)
		{
			this.offeredCipherSuites = offeredCipherSuites;
			this.eccCipherSuitesOffered = TlsECCUtils.containsECCCipherSuites(this.offeredCipherSuites);
		}

		public virtual void notifyOfferedCompressionMethods(short[] offeredCompressionMethods)
		{
			this.offeredCompressionMethods = offeredCompressionMethods;
		}

		public virtual void processClientExtensions(Hashtable clientExtensions)
		{
			this.clientExtensions = clientExtensions;

			if (clientExtensions != null)
			{
				this.encryptThenMACOffered = TlsExtensionsUtils.hasEncryptThenMACExtension(clientExtensions);

				this.maxFragmentLengthOffered = TlsExtensionsUtils.getMaxFragmentLengthExtension(clientExtensions);
				if (maxFragmentLengthOffered >= 0 && !MaxFragmentLength.isValid(maxFragmentLengthOffered))
				{
					throw new TlsFatalAlert(AlertDescription.illegal_parameter);
				}

				this.truncatedHMacOffered = TlsExtensionsUtils.hasTruncatedHMacExtension(clientExtensions);

				this.supportedSignatureAlgorithms = TlsUtils.getSignatureAlgorithmsExtension(clientExtensions);
				if (this.supportedSignatureAlgorithms != null)
				{
					/*
					 * RFC 5246 7.4.1.4.1. Note: this extension is not meaningful for TLS versions prior
					 * to 1.2. Clients MUST NOT offer it if they are offering prior versions.
					 */
					if (!TlsUtils.isSignatureAlgorithmsExtensionAllowed(clientVersion))
					{
						throw new TlsFatalAlert(AlertDescription.illegal_parameter);
					}
				}

				this.namedCurves = TlsECCUtils.getSupportedEllipticCurvesExtension(clientExtensions);
				this.clientECPointFormats = TlsECCUtils.getSupportedPointFormatsExtension(clientExtensions);
			}

			/*
			 * RFC 4429 4. The client MUST NOT include these extensions in the ClientHello message if it
			 * does not propose any ECC cipher suites.
			 * 
			 * NOTE: This was overly strict as there may be ECC cipher suites that we don't recognize.
			 * Also, draft-ietf-tls-negotiated-ff-dhe will be overloading the 'elliptic_curves'
			 * extension to explicitly allow FFDHE (i.e. non-ECC) groups.
			 */
	//        if (!this.eccCipherSuitesOffered && (this.namedCurves != null || this.clientECPointFormats != null))
	//        {
	//            throw new TlsFatalAlert(AlertDescription.illegal_parameter);
	//        }
		}

		public virtual ProtocolVersion getServerVersion()
		{
			if (getMinimumVersion().isEqualOrEarlierVersionOf(clientVersion))
			{
				ProtocolVersion maximumVersion = getMaximumVersion();
				if (clientVersion.isEqualOrEarlierVersionOf(maximumVersion))
				{
					return serverVersion = clientVersion;
				}
				if (clientVersion.isLaterVersionOf(maximumVersion))
				{
					return serverVersion = maximumVersion;
				}
			}
			throw new TlsFatalAlert(AlertDescription.protocol_version);
		}

		public virtual int getSelectedCipherSuite()
		{
			/*
			 * RFC 5246 7.4.3. In order to negotiate correctly, the server MUST check any candidate
			 * cipher suites against the "signature_algorithms" extension before selecting them. This is
			 * somewhat inelegant but is a compromise designed to minimize changes to the original
			 * cipher suite design.
			 */
			Vector sigAlgs = TlsUtils.getUsableSignatureAlgorithms(supportedSignatureAlgorithms);

			/*
			 * RFC 4429 5.1. A server that receives a ClientHello containing one or both of these
			 * extensions MUST use the client's enumerated capabilities to guide its selection of an
			 * appropriate cipher suite. One of the proposed ECC cipher suites must be negotiated only
			 * if the server can successfully complete the handshake while using the curves and point
			 * formats supported by the client [...].
			 */
			bool eccCipherSuitesEnabled = supportsClientECCCapabilities(this.namedCurves, this.clientECPointFormats);

			int[] cipherSuites = getCipherSuites();
			for (int i = 0; i < cipherSuites.Length; ++i)
			{
				int cipherSuite = cipherSuites[i];

				if (Arrays.contains(this.offeredCipherSuites, cipherSuite) && (eccCipherSuitesEnabled || !TlsECCUtils.isECCCipherSuite(cipherSuite)) && TlsUtils.isValidCipherSuiteForVersion(cipherSuite, serverVersion) && TlsUtils.isValidCipherSuiteForSignatureAlgorithms(cipherSuite, sigAlgs))
				{
					return this.selectedCipherSuite = cipherSuite;
				}
			}
			throw new TlsFatalAlert(AlertDescription.handshake_failure);
		}

		public virtual short getSelectedCompressionMethod()
		{
			short[] compressionMethods = getCompressionMethods();
			for (int i = 0; i < compressionMethods.Length; ++i)
			{
				if (Arrays.contains(offeredCompressionMethods, compressionMethods[i]))
				{
					return this.selectedCompressionMethod = compressionMethods[i];
				}
			}
			throw new TlsFatalAlert(AlertDescription.handshake_failure);
		}

		// Hashtable is (Integer -> byte[])
		public virtual Hashtable getServerExtensions()
		{
			if (this.encryptThenMACOffered && allowEncryptThenMAC())
			{
				/*
				 * RFC 7366 3. If a server receives an encrypt-then-MAC request extension from a client
				 * and then selects a stream or Authenticated Encryption with Associated Data (AEAD)
				 * ciphersuite, it MUST NOT send an encrypt-then-MAC response extension back to the
				 * client.
				 */
				if (TlsUtils.isBlockCipherSuite(this.selectedCipherSuite))
				{
					TlsExtensionsUtils.addEncryptThenMACExtension(checkServerExtensions());
				}
			}

			if (this.maxFragmentLengthOffered >= 0 && MaxFragmentLength.isValid(maxFragmentLengthOffered))
			{
				TlsExtensionsUtils.addMaxFragmentLengthExtension(checkServerExtensions(), this.maxFragmentLengthOffered);
			}

			if (this.truncatedHMacOffered && allowTruncatedHMac())
			{
				TlsExtensionsUtils.addTruncatedHMacExtension(checkServerExtensions());
			}

			if (this.clientECPointFormats != null && TlsECCUtils.isECCCipherSuite(this.selectedCipherSuite))
			{
				/*
				 * RFC 4492 5.2. A server that selects an ECC cipher suite in response to a ClientHello
				 * message including a Supported Point Formats Extension appends this extension (along
				 * with others) to its ServerHello message, enumerating the point formats it can parse.
				 */
				this.serverECPointFormats = new short[]{ECPointFormat.uncompressed, ECPointFormat.ansiX962_compressed_prime, ECPointFormat.ansiX962_compressed_char2};

				TlsECCUtils.addSupportedPointFormatsExtension(checkServerExtensions(), serverECPointFormats);
			}

			return serverExtensions;
		}

		public virtual Vector getServerSupplementalData()
		{
			return null;
		}

		public virtual CertificateStatus getCertificateStatus()
		{
			return null;
		}

		public virtual CertificateRequest getCertificateRequest()
		{
			return null;
		}

		public virtual void processClientSupplementalData(Vector clientSupplementalData)
		{
			if (clientSupplementalData != null)
			{
				throw new TlsFatalAlert(AlertDescription.unexpected_message);
			}
		}

		public virtual void notifyClientCertificate(Certificate clientCertificate)
		{
			throw new TlsFatalAlert(AlertDescription.internal_error);
		}

		public override TlsCompression getCompression()
		{
			switch (selectedCompressionMethod)
			{
			case CompressionMethod._null:
				return new TlsNullCompression();

			default:
				/*
				 * Note: internal error here; we selected the compression method, so if we now can't
				 * produce an implementation, we shouldn't have chosen it!
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

		public virtual NewSessionTicket getNewSessionTicket()
		{
			/*
			 * RFC 5077 3.3. If the server determines that it does not want to include a ticket after it
			 * has included the SessionTicket extension in the ServerHello, then it sends a zero-length
			 * ticket in the NewSessionTicket handshake message.
			 */
			return new NewSessionTicket(0L, TlsUtils.EMPTY_BYTES);
		}
	}

}