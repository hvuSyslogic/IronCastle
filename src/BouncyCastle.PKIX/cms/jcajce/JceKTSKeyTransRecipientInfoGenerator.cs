using org.bouncycastle.asn1;

using System;

namespace org.bouncycastle.cms.jcajce
{

	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using IssuerAndSerialNumber = org.bouncycastle.asn1.cms.IssuerAndSerialNumber;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
	using JceAsymmetricKeyWrapper = org.bouncycastle.@operator.jcajce.JceAsymmetricKeyWrapper;
	using JceKTSKeyWrapper = org.bouncycastle.@operator.jcajce.JceKTSKeyWrapper;
	using Hex = org.bouncycastle.util.encoders.Hex;

	public class JceKTSKeyTransRecipientInfoGenerator : KeyTransRecipientInfoGenerator
	{
		private static readonly byte[] ANONYMOUS_SENDER = Hex.decode("0c14416e6f6e796d6f75732053656e64657220202020"); // "Anonymous Sender    "

		private JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, IssuerAndSerialNumber recipientID, string symmetricWrappingAlg, int keySizeInBits) : base(recipientID, new JceKTSKeyWrapper(recipientCert, symmetricWrappingAlg, keySizeInBits, ANONYMOUS_SENDER, getEncodedRecipID(recipientID)))
		{
		}

		public JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, string symmetricWrappingAlg, int keySizeInBits) : this(recipientCert, new IssuerAndSerialNumber((new JcaX509CertificateHolder(recipientCert)).toASN1Structure()), symmetricWrappingAlg, keySizeInBits)
		{
		}

		public JceKTSKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey, string symmetricWrappingAlg, int keySizeInBits) : base(subjectKeyIdentifier, new JceKTSKeyWrapper(publicKey, symmetricWrappingAlg, keySizeInBits, ANONYMOUS_SENDER, getEncodedSubKeyId(subjectKeyIdentifier)))
		{
		}

		private static byte[] getEncodedRecipID(IssuerAndSerialNumber recipientID)
		{
			try
			{
				return recipientID.getEncoded(ASN1Encoding_Fields.DER);
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final java.io.IOException e)
			catch (IOException e)
			{
				throw new CertificateEncodingExceptionAnonymousInnerClass("Cannot process extracted IssuerAndSerialNumber: " + e.Message, e);
			}
		}

		public class CertificateEncodingExceptionAnonymousInnerClass : CertificateEncodingException
		{
			private va.io.IOException e;

			public CertificateEncodingExceptionAnonymousInnerClass(string getMessage, va.io.IOException e) : base(getMessage)
			{
				this.e = e;
			}

			public Exception getCause()
			{
				return e;
			}
		}

		private static byte[] getEncodedSubKeyId(byte[] subjectKeyIdentifier)
		{
			try
			{
				return (new DEROctetString(subjectKeyIdentifier)).getEncoded();
			}
//JAVA TO C# CONVERTER WARNING: 'final' catch parameters are not available in C#:
//ORIGINAL LINE: catch (final java.io.IOException e)
			catch (IOException e)
			{
				throw new IllegalArgumentExceptionAnonymousInnerClass("Cannot process subject key identifier: " + e.Message, e);
			}
		}

		public class IllegalArgumentExceptionAnonymousInnerClass : IllegalArgumentException
		{
			private va.io.IOException e;

			public IllegalArgumentExceptionAnonymousInnerClass(string getMessage, va.io.IOException e) : base(getMessage)
			{
				this.e = e;
			}

			public Exception getCause()
			{
				return e;
			}
		}

		/// <summary>
		/// Create a generator overriding the algorithm type implied by the public key in the certificate passed in.
		/// </summary>
		/// <param name="recipientCert">       certificate carrying the public key. </param>
		/// <param name="algorithmIdentifier"> the identifier and parameters for the encryption algorithm to be used. </param>
		public JceKTSKeyTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmIdentifier algorithmIdentifier) : base(new IssuerAndSerialNumber((new JcaX509CertificateHolder(recipientCert)).toASN1Structure()), new JceAsymmetricKeyWrapper(algorithmIdentifier, recipientCert.getPublicKey()))
		{
		}

		/// <summary>
		/// Create a generator overriding the algorithm type implied by the public key passed in.
		/// </summary>
		/// <param name="subjectKeyIdentifier"> the subject key identifier value to associate with the public key. </param>
		/// <param name="algorithmIdentifier">  the identifier and parameters for the encryption algorithm to be used. </param>
		/// <param name="publicKey">            the public key to use. </param>
		public JceKTSKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, AlgorithmIdentifier algorithmIdentifier, PublicKey publicKey) : base(subjectKeyIdentifier, new JceAsymmetricKeyWrapper(algorithmIdentifier, publicKey))
		{
		}

		public virtual JceKTSKeyTransRecipientInfoGenerator setProvider(string providerName)
		{
			((JceKTSKeyWrapper)this.wrapper).setProvider(providerName);

			return this;
		}

		public virtual JceKTSKeyTransRecipientInfoGenerator setProvider(Provider provider)
		{
			((JceKTSKeyWrapper)this.wrapper).setProvider(provider);

			return this;
		}
	}
}