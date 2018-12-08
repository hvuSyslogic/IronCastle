using System;

namespace org.bouncycastle.cert.jcajce
{

	using Certificate = org.bouncycastle.asn1.x509.Certificate;

	/// <summary>
	/// JCA helper class for converting an X509Certificate into a X509CertificateHolder object.
	/// </summary>
	[Serializable]
	public class JcaX509CertificateHolder : X509CertificateHolder
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="cert"> certificate to be used a the source for the holder creation. </param>
		/// <exception cref="CertificateEncodingException"> if there is a problem extracting the certificate information. </exception>
		public JcaX509CertificateHolder(X509Certificate cert) : base(Certificate.getInstance(cert.getEncoded()))
		{
		}
	}

}