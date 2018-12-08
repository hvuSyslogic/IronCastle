namespace org.bouncycastle.@operator.bc
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Signer = org.bouncycastle.crypto.Signer;
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public abstract class BcContentVerifierProviderBuilder
	{
		protected internal BcDigestProvider digestProvider;

		public BcContentVerifierProviderBuilder()
		{
			this.digestProvider = BcDefaultDigestProvider.INSTANCE;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.ContentVerifierProvider build(final org.bouncycastle.cert.X509CertificateHolder certHolder) throws org.bouncycastle.operator.OperatorCreationException
		public virtual ContentVerifierProvider build(X509CertificateHolder certHolder)
		{
			return new ContentVerifierProviderAnonymousInnerClass(this, certHolder);
		}

		public class ContentVerifierProviderAnonymousInnerClass : ContentVerifierProvider
		{
			private readonly BcContentVerifierProviderBuilder outerInstance;

			private X509CertificateHolder certHolder;

			public ContentVerifierProviderAnonymousInnerClass(BcContentVerifierProviderBuilder outerInstance, X509CertificateHolder certHolder)
			{
				this.outerInstance = outerInstance;
				this.certHolder = certHolder;
			}

			public bool hasAssociatedCertificate()
			{
				return true;
			}

			public X509CertificateHolder getAssociatedCertificate()
			{
				return certHolder;
			}

			public ContentVerifier get(AlgorithmIdentifier algorithm)
			{
				try
				{
					AsymmetricKeyParameter publicKey = outerInstance.extractKeyParameters(certHolder.getSubjectPublicKeyInfo());
					BcSignerOutputStream stream = outerInstance.createSignatureStream(algorithm, publicKey);

					return new SigVerifier(outerInstance, algorithm, stream);
				}
				catch (IOException e)
				{
					throw new OperatorCreationException("exception on setup: " + e, e);
				}
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.ContentVerifierProvider build(final org.bouncycastle.crypto.params.AsymmetricKeyParameter publicKey) throws org.bouncycastle.operator.OperatorCreationException
		public virtual ContentVerifierProvider build(AsymmetricKeyParameter publicKey)
		{
			return new ContentVerifierProviderAnonymousInnerClass2(this, publicKey);
		}

		public class ContentVerifierProviderAnonymousInnerClass2 : ContentVerifierProvider
		{
			private readonly BcContentVerifierProviderBuilder outerInstance;

			private AsymmetricKeyParameter publicKey;

			public ContentVerifierProviderAnonymousInnerClass2(BcContentVerifierProviderBuilder outerInstance, AsymmetricKeyParameter publicKey)
			{
				this.outerInstance = outerInstance;
				this.publicKey = publicKey;
			}

			public bool hasAssociatedCertificate()
			{
				return false;
			}

			public X509CertificateHolder getAssociatedCertificate()
			{
				return null;
			}

			public ContentVerifier get(AlgorithmIdentifier algorithm)
			{
				BcSignerOutputStream stream = outerInstance.createSignatureStream(algorithm, publicKey);

				return new SigVerifier(outerInstance, algorithm, stream);
			}
		}

		private BcSignerOutputStream createSignatureStream(AlgorithmIdentifier algorithm, AsymmetricKeyParameter publicKey)
		{
			Signer sig = createSigner(algorithm);

			sig.init(false, publicKey);

			return new BcSignerOutputStream(sig);
		}

		/// <summary>
		/// Extract an AsymmetricKeyParameter from the passed in SubjectPublicKeyInfo structure.
		/// </summary>
		/// <param name="publicKeyInfo"> a publicKeyInfo structure describing the public key required. </param>
		/// <returns> an AsymmetricKeyParameter object containing the appropriate public key. </returns>
		/// <exception cref="IOException"> if the publicKeyInfo data cannot be parsed, </exception>
		public abstract AsymmetricKeyParameter extractKeyParameters(SubjectPublicKeyInfo publicKeyInfo);

		/// <summary>
		/// Create the correct signer for the algorithm identifier sigAlgId.
		/// </summary>
		/// <param name="sigAlgId"> the algorithm details for the signature we want to verify. </param>
		/// <returns> a Signer object. </returns>
		/// <exception cref="OperatorCreationException"> if the Signer cannot be constructed. </exception>
		public abstract Signer createSigner(AlgorithmIdentifier sigAlgId);

		public class SigVerifier : ContentVerifier
		{
			private readonly BcContentVerifierProviderBuilder outerInstance;

			internal BcSignerOutputStream stream;
			internal AlgorithmIdentifier algorithm;

			public SigVerifier(BcContentVerifierProviderBuilder outerInstance, AlgorithmIdentifier algorithm, BcSignerOutputStream stream)
			{
				this.outerInstance = outerInstance;
				this.algorithm = algorithm;
				this.stream = stream;
			}

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return algorithm;
			}

			public virtual OutputStream getOutputStream()
			{
				if (stream == null)
				{
					throw new IllegalStateException("verifier not initialised");
				}

				return stream;
			}

			public virtual bool verify(byte[] expected)
			{
				return stream.verify(expected);
			}
		}
	}
}