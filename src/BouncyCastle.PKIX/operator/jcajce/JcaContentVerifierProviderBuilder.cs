using System;

namespace org.bouncycastle.@operator.jcajce
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using OutputStreamFactory = org.bouncycastle.jcajce.io.OutputStreamFactory;
	using DefaultJcaJceHelper = org.bouncycastle.jcajce.util.DefaultJcaJceHelper;
	using NamedJcaJceHelper = org.bouncycastle.jcajce.util.NamedJcaJceHelper;
	using ProviderJcaJceHelper = org.bouncycastle.jcajce.util.ProviderJcaJceHelper;

	public class JcaContentVerifierProviderBuilder
	{
		private OperatorHelper helper = new OperatorHelper(new DefaultJcaJceHelper());

		public JcaContentVerifierProviderBuilder()
		{
		}

		public virtual JcaContentVerifierProviderBuilder setProvider(Provider provider)
		{
			this.helper = new OperatorHelper(new ProviderJcaJceHelper(provider));

			return this;
		}

		public virtual JcaContentVerifierProviderBuilder setProvider(string providerName)
		{
			this.helper = new OperatorHelper(new NamedJcaJceHelper(providerName));

			return this;
		}

		public virtual ContentVerifierProvider build(X509CertificateHolder certHolder)
		{
			return build(helper.convertCertificate(certHolder));
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.ContentVerifierProvider build(final java.security.cert.X509Certificate certificate) throws org.bouncycastle.operator.OperatorCreationException
		public virtual ContentVerifierProvider build(X509Certificate certificate)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final org.bouncycastle.cert.X509CertificateHolder certHolder;
			X509CertificateHolder certHolder;

			try
			{
				certHolder = new JcaX509CertificateHolder(certificate);
			}
			catch (CertificateEncodingException e)
			{
				throw new OperatorCreationException("cannot process certificate: " + e.Message, e);
			}

			return new ContentVerifierProviderAnonymousInnerClass(this, certificate, certHolder, e);
		}

		public class ContentVerifierProviderAnonymousInnerClass : ContentVerifierProvider
		{
			private readonly JcaContentVerifierProviderBuilder outerInstance;

			private X509Certificate certificate;
			private X509CertificateHolder certHolder;
			private CertificateEncodingException e;

			public ContentVerifierProviderAnonymousInnerClass(JcaContentVerifierProviderBuilder outerInstance, X509Certificate certificate, X509CertificateHolder certHolder, CertificateEncodingException e)
			{
				this.outerInstance = outerInstance;
				this.certificate = certificate;
				this.certHolder = certHolder;
				this.e = e;
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
				Signature sig;
				try
				{
					sig = outerInstance.helper.createSignature(algorithm);

					sig.initVerify(certificate.getPublicKey());
				}
				catch (GeneralSecurityException e)
				{
					throw new OperatorCreationException("exception on setup: " + e, e);
				}

				Signature rawSig = outerInstance.createRawSig(algorithm, certificate.getPublicKey());

				if (rawSig != null)
				{
					return new RawSigVerifier(outerInstance, algorithm, sig, rawSig);
				}
				else
				{
					return new SigVerifier(outerInstance, algorithm, sig);
				}
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.operator.ContentVerifierProvider build(final java.security.PublicKey publicKey) throws org.bouncycastle.operator.OperatorCreationException
		public virtual ContentVerifierProvider build(PublicKey publicKey)
		{
			return new ContentVerifierProviderAnonymousInnerClass2(this, publicKey);
		}

		public class ContentVerifierProviderAnonymousInnerClass2 : ContentVerifierProvider
		{
			private readonly JcaContentVerifierProviderBuilder outerInstance;

			private PublicKey publicKey;

			public ContentVerifierProviderAnonymousInnerClass2(JcaContentVerifierProviderBuilder outerInstance, PublicKey publicKey)
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
				Signature sig = outerInstance.createSignature(algorithm, publicKey);

				Signature rawSig = outerInstance.createRawSig(algorithm, publicKey);

				if (rawSig != null)
				{
					return new RawSigVerifier(outerInstance, algorithm, sig, rawSig);
				}
				else
				{
					return new SigVerifier(outerInstance, algorithm, sig);
				}
			}
		}

		public virtual ContentVerifierProvider build(SubjectPublicKeyInfo publicKey)
		{
			return this.build(helper.convertPublicKey(publicKey));
		}

		private Signature createSignature(AlgorithmIdentifier algorithm, PublicKey publicKey)
		{
			try
			{
				Signature sig = helper.createSignature(algorithm);

				sig.initVerify(publicKey);

				return sig;
			}
			catch (GeneralSecurityException e)
			{
				throw new OperatorCreationException("exception on setup: " + e, e);
			}
		}

		private Signature createRawSig(AlgorithmIdentifier algorithm, PublicKey publicKey)
		{
			Signature rawSig;
			try
			{
				rawSig = helper.createRawSignature(algorithm);

				if (rawSig != null)
				{
					rawSig.initVerify(publicKey);
				}
			}
			catch (Exception)
			{
				rawSig = null;
			}
			return rawSig;
		}

		public class SigVerifier : ContentVerifier
		{
			private readonly JcaContentVerifierProviderBuilder outerInstance;

			internal readonly AlgorithmIdentifier algorithm;
			internal readonly Signature signature;

			protected internal readonly OutputStream stream;

			public SigVerifier(JcaContentVerifierProviderBuilder outerInstance, AlgorithmIdentifier algorithm, Signature signature)
			{
				this.outerInstance = outerInstance;
				this.algorithm = algorithm;
				this.signature = signature;
				this.stream = OutputStreamFactory.createStream(signature);
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
				try
				{
					return signature.verify(expected);
				}
				catch (SignatureException e)
				{
					throw new RuntimeOperatorException("exception obtaining signature: " + e.Message, e);
				}
			}
		}

		public class RawSigVerifier : SigVerifier, RawContentVerifier
		{
			private readonly JcaContentVerifierProviderBuilder outerInstance;

			internal Signature rawSignature;

			public RawSigVerifier(JcaContentVerifierProviderBuilder outerInstance, AlgorithmIdentifier algorithm, Signature standardSig, Signature rawSignature) : base(outerInstance, algorithm, standardSig)
			{
				this.outerInstance = outerInstance;
				this.rawSignature = rawSignature;
			}

			public override bool verify(byte[] expected)
			{
				try
				{
					return base.verify(expected);
				}
				finally
				{
					// we need to do this as in some PKCS11 implementations the session associated with the init of the
					// raw signature will not be freed if verify is not called on it.
					try
					{
						rawSignature.verify(expected);
					}
					catch (Exception)
					{
						// ignore
					}
				}
			}

			public virtual bool verify(byte[] digest, byte[] expected)
			{
				try
				{
					rawSignature.update(digest);

					return rawSignature.verify(expected);
				}
				catch (SignatureException e)
				{
					throw new RuntimeOperatorException("exception obtaining raw signature: " + e.Message, e);
				}
				finally
				{
					// we need to do this as in some PKCS11 implementations the session associated with the init of the
					// standard signature will not be freed if verify is not called on it.
					try
					{
						rawSignature.verify(expected);
					}
					catch (Exception)
					{
						// ignore
					}
				}
			}
		}
	}
}