namespace org.bouncycastle.openssl
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Object = org.bouncycastle.asn1.ASN1Object;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Holder for an OpenSSL trusted certificate block.
	/// </summary>
	public class X509TrustedCertificateBlock
	{
		private readonly X509CertificateHolder certificateHolder;
		private readonly CertificateTrustBlock trustBlock;

		public X509TrustedCertificateBlock(X509CertificateHolder certificateHolder, CertificateTrustBlock trustBlock)
		{
			this.certificateHolder = certificateHolder;
			this.trustBlock = trustBlock;
		}

		public X509TrustedCertificateBlock(byte[] encoding)
		{
			ASN1InputStream aIn = new ASN1InputStream(encoding);

			this.certificateHolder = new X509CertificateHolder(aIn.readObject().getEncoded());

			ASN1Object tBlock = aIn.readObject();

			if (tBlock != null)
			{
				this.trustBlock = new CertificateTrustBlock(tBlock.getEncoded());
			}
			else
			{
				this.trustBlock = null;
			}
		}

		public virtual byte[] getEncoded()
		{
			return Arrays.concatenate(certificateHolder.getEncoded(), trustBlock.toASN1Sequence().getEncoded());
		}

		/// <summary>
		/// Return the certificate associated with this Trusted Certificate
		/// </summary>
		/// <returns> the certificate holder. </returns>
		public virtual X509CertificateHolder getCertificateHolder()
		{
			return certificateHolder;
		}

		/// <summary>
		/// Return the trust block associated with this Trusted Certificate
		/// </summary>
		/// <returns> the trust block. </returns>
		public virtual CertificateTrustBlock getTrustBlock()
		{
			return trustBlock;
		}
	}

}