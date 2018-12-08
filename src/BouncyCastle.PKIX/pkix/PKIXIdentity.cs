namespace org.bouncycastle.pkix
{
	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using KeyTransRecipientId = org.bouncycastle.cms.KeyTransRecipientId;
	using RecipientId = org.bouncycastle.cms.RecipientId;

	/// <summary>
	/// Holder class for public/private key based identity information.
	/// </summary>
	public class PKIXIdentity
	{
		private readonly PrivateKeyInfo privateKeyInfo;
		private readonly X509CertificateHolder[] certificateHolders;

		public PKIXIdentity(PrivateKeyInfo privateKeyInfo, X509CertificateHolder[] certificateHolders)
		{
			this.privateKeyInfo = privateKeyInfo;
			this.certificateHolders = new X509CertificateHolder[certificateHolders.Length];
			JavaSystem.arraycopy(certificateHolders, 0, this.certificateHolders, 0, certificateHolders.Length);
		}

		/// <summary>
		/// Return the private key info for this identity.
		/// </summary>
		/// <returns> the identity's private key (if available, null otherwise). </returns>
		public virtual PrivateKeyInfo getPrivateKeyInfo()
		{
			return privateKeyInfo;
		}

		/// <summary>
		/// Return the certificate associated with the private key info.
		/// </summary>
		/// <returns> a X509CertificateHolder </returns>
		public virtual X509CertificateHolder getCertificate()
		{
			return certificateHolders[0];
		}

		/// <summary>
		/// Return a RecipientId for the identity's (private key, certificate) pair.
		/// </summary>
		public virtual RecipientId getRecipientId()
		{
			// TODO: handle key agreement
			return new KeyTransRecipientId(certificateHolders[0].getIssuer(), certificateHolders[0].getSerialNumber(), getSubjectKeyIdentifier());
		}

		private byte[] getSubjectKeyIdentifier()
		{
			SubjectKeyIdentifier subId = SubjectKeyIdentifier.fromExtensions(certificateHolders[0].getExtensions());

			if (subId == null)
			{
				return null;
			}

			return subId.getKeyIdentifier();
		}
	}

}