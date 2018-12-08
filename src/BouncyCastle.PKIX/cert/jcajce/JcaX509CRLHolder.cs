using System;

namespace org.bouncycastle.cert.jcajce
{

	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;

	/// <summary>
	/// JCA helper class for converting an X509CRL into a X509CRLHolder object.
	/// </summary>
	[Serializable]
	public class JcaX509CRLHolder : X509CRLHolder
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="crl"> CRL to be used a the source for the holder creation. </param>
		/// <exception cref="CRLException"> if there is a problem extracting the CRL information. </exception>
		public JcaX509CRLHolder(X509CRL crl) : base(CertificateList.getInstance(crl.getEncoded()))
		{
		}
	}

}