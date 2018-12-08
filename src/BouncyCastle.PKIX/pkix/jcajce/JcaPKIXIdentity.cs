using System;

namespace org.bouncycastle.pkix.jcajce
{

	using PrivateKeyInfo = org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using JcaX509CertificateHolder = org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

	/// <summary>
	/// Holder class for public/private key based identity information.
	/// </summary>
	public class JcaPKIXIdentity : PKIXIdentity
	{
		private readonly PrivateKey privKey;
		private readonly X509Certificate[] certs;

		private static PrivateKeyInfo getPrivateKeyInfo(PrivateKey privateKey)
		{
			 try
			 {
				 return PrivateKeyInfo.getInstance(privateKey.getEncoded());
			 }
			 catch (Exception) // for a HSM getEncoded() may do anything...
			 {
				 return null;
			 }
		}

		private static X509CertificateHolder[] getCertificates(X509Certificate[] certs)
		{
			X509CertificateHolder[] certHldrs = new X509CertificateHolder[certs.Length];

			try
			{
				for (int i = 0; i != certHldrs.Length; i++)
				{
					certHldrs[i] = new JcaX509CertificateHolder(certs[i]);
				}

				return certHldrs;
			}
			catch (CertificateEncodingException e)
			{
				throw new IllegalArgumentException("Unable to process certificates: " + e.Message);
			}
		}

		public JcaPKIXIdentity(PrivateKey privKey, X509Certificate[] certs) : base(getPrivateKeyInfo(privKey), getCertificates(certs))
		{

			this.privKey = privKey;
			this.certs = new X509Certificate[certs.Length];

			JavaSystem.arraycopy(certs, 0, this.certs, 0, certs.Length);
		}

		/// <summary>
		/// Return the private key for this identity.
		/// </summary>
		/// <returns> the identity's private key. </returns>
		public virtual PrivateKey getPrivateKey()
		{
			return privKey;
		}

		/// <summary>
		/// Return the certificate associated with the private key.
		/// </summary>
		/// <returns> the primary certificate. </returns>
		public virtual X509Certificate getX509Certificate()
		{
			return certs[0];
		}
	}

}